package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-yaml/yaml"
)

func main() {
	start := time.Now()

	listen := os.Getenv("LISTEN_ADDRESS")
	basicAuth := BasicAuth{
		Username: os.Getenv("SPRING_CLOUD_USER"),
		Password: os.Getenv("SPRING_CLOUD_PASSWORD"),
	}
	azureGitClient := makeAzureGitClient(AzureGitConfig{
		Token:        os.Getenv("GIT_TOKEN"),
		Organization: os.Getenv("GIT_ORGANIZATION"),
		Project:      os.Getenv("GIT_PROJECT"),
		Repository:   os.Getenv("GIT_REPOSITORY"),
	})

	var mux http.ServeMux
	{
		configs, err := azureGitClient.GetConfigs()
		if err != nil {
			panic(err)
		}
		log.Println("available configurations:", configs)
		for _, config := range configs {
			mux.HandleFunc("/"+config+".yml",
				makeYamlConfigHandler(config, &basicAuth, &azureGitClient))
			mux.HandleFunc("/"+config+".json",
				makeJsonConfigHandler(config, &basicAuth, &azureGitClient))
			mux.HandleFunc("/"+config+"/",
				makeSpringConfigHandler(config, &basicAuth, &azureGitClient))
		}
	}
	log.Println("started in", time.Since(start), "and listening at", listen)
	if err := http.ListenAndServe(listen, &mux); err != nil {
		panic(err)
	}
}

func makeYamlConfigHandler(config string, ba *BasicAuth, agg *AzureGitClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ba.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		item, err := agg.GetItem(config + ".yml")
		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		if err := agg.DownloadConfigTo(item.URL, w); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}
}

func makeJsonConfigHandler(config string, ba *BasicAuth, agg *AzureGitClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ba.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		item, err := agg.GetItem(config + ".yml")
		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		configset, err := agg.DownloadConfig(item.URL)
		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		stringified := stringifyMap(configset)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		if err := json.NewEncoder(w).Encode(stringified); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}
}

func makeSpringConfigHandler(config string, ba *BasicAuth, agg *AzureGitClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ba.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		item, err := agg.GetItem(config + ".yml")
		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		configset, err := agg.DownloadConfig(item.URL)
		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		flattened := flattenMap(configset)
		type PropertySource struct {
			Name   string                 `json:"name"`
			Source map[string]interface{} `json:"source"`
		}
		cloudConfigAnswer := struct {
			Name            string           `json:"name"`
			Profiles        []string         `json:"profiles"`
			Label           interface{}      `json:"label"`
			Version         string           `json:"version"`
			State           interface{}      `json:"state"`
			PropertySources []PropertySource `json:"propertySources"`
		}{
			Name:     config,
			Profiles: []string{"default"},
			Version:  item.CommitID,
			PropertySources: []PropertySource{
				PropertySource{
					Name:   config + ".yml",
					Source: flattened,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		if err := json.NewEncoder(w).Encode(cloudConfigAnswer); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}
}

type BasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (ba *BasicAuth) IsAuthorized(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	return ok && ba.Username == username && ba.Password == password
}

type AzureGitConfig struct {
	Token        string `json:"token"`
	Organization string `json:"organization"`
	Project      string `json:"project"`
	Repository   string `json:"repository"`
}

type AzureGitClient struct {
	basePath string
	token    string
	cli      http.Client
}

func makeAzureGitClient(config AzureGitConfig) AzureGitClient {
	return AzureGitClient{
		basePath: fmt.Sprintf(
			"https://dev.azure.com/%s/%s/_apis/git/repositories/%s/items?",
			config.Organization, config.Project, config.Repository),
		token: config.Token,
		cli: http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (agc *AzureGitClient) GetConfigs() ([]string, error) {
	vals := url.Values{
		"api-version":    []string{"5.1"},
		"recursionLevel": []string{"oneLevel"},
	}
	req, err := http.NewRequest("GET", agc.basePath+vals.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth("Personal Access Token", agc.token)
	r, err := agc.cli.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return nil, errors.New("status not ok")
	}
	var results struct {
		Value []struct {
			Path string `json:"path"`
		} `json:"value"`
	}
	err = json.NewDecoder(r.Body).Decode(&results)
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	configs := make([]string, 0, len(results.Value))
	for _, value := range results.Value {
		if !strings.HasSuffix(value.Path, ".yml") {
			continue
		}
		p := value.Path[1 : len(value.Path)-len(".yml")]
		configs = append(configs, p)
	}
	return configs, nil
}

func (agc *AzureGitClient) GetItem(path string) (Item, error) {
	var item Item
	vals := url.Values{
		"scopePath":   []string{path},
		"download":    []string{"true"},
		"api-version": []string{"5.1"},
	}
	req, err := http.NewRequest("GET", agc.basePath+vals.Encode(), nil)
	if err != nil {
		return item, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth("Personal Access Token", agc.token)
	r, err := agc.cli.Do(req)
	if err != nil {
		return item, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return item, errors.New("status not ok")
	}
	var itemDownload ItemDownload
	json.NewDecoder(r.Body).Decode(&itemDownload)
	r.Body.Close()
	if len(itemDownload.Value) != 1 {
		return item, errors.New("no item found")
	}
	return itemDownload.Value[0], err
}

func (agc *AzureGitClient) DownloadConfig(path string) (map[interface{}]interface{}, error) {
	var configset map[interface{}]interface{}
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return configset, err
	}
	req.SetBasicAuth("Personal Access Token", agc.token)
	r, err := agc.cli.Do(req)
	if err != nil {
		return configset, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return configset, errors.New("status not ok")
	}
	err = yaml.NewDecoder(r.Body).Decode(&configset)
	r.Body.Close()
	return configset, err
}

func (agc *AzureGitClient) DownloadConfigTo(path string, w io.Writer) error {
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth("Personal Access Token", agc.token)
	r, err := agc.cli.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return errors.New("status not ok")
	}
	_, err = io.Copy(w, r.Body)
	r.Body.Close()
	return err
}

type Item struct {
	CommitID string `json:"commitId"`
	URL      string `json:"url"`
}

type ItemDownload struct {
	Value []Item `json:"value"`
}

func flattenMap(m map[interface{}]interface{}) map[string]interface{} {
	o := make(map[string]interface{})
	for k, v := range m {
		switch child := v.(type) {
		case map[interface{}]interface{}:
			nm := flattenMap(child)
			for nk, nv := range nm {
				o[k.(string)+"."+nk] = nv
			}
		case []interface{}:
			for i := 0; i < len(child); i++ {
				ks := fmt.Sprintf("%s[%d]", k.(string), i)
				o[ks] = child[i]
			}
		default:
			if v == nil {
				o[k.(string)] = ""
			} else {
				o[k.(string)] = v
			}
		}
	}
	return o
}

func stringifyMap(m map[interface{}]interface{}) map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range m {
		switch v2 := v.(type) {
		case map[interface{}]interface{}:
			res[fmt.Sprint(k)] = stringifyMap(v2)
		case []interface{}:
			res[fmt.Sprint(k)] = stringifySlice(v2)
		default:
			res[fmt.Sprint(k)] = v
		}
	}
	return res
}

func stringifySlice(s []interface{}) []interface{} {
	for i, el := range s {
		switch v2 := el.(type) {
		case map[interface{}]interface{}:
			s[i] = stringifyMap(v2)
		case []interface{}:
			s[i] = stringifySlice(v2)
		}
	}
	return s
}
