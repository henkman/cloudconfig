package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	var (
		listen         string
		basicAuth      BasicAuth
		azureGitClient AzureGitClient
	)
	{
		var config struct {
			Listen         string         `json:"listen"`
			BasicAuth      BasicAuth      `json:"basicAuth`
			AzureGitConfig AzureGitConfig `json:"azure"`
		}
		fd, err := os.Open("application.json")
		if err != nil {
			panic(err)
		}
		err = json.NewDecoder(fd).Decode(&config)
		fd.Close()
		if err != nil {
			panic(err)
		}
		listen = config.Listen
		basicAuth = config.BasicAuth
		azureGitClient = makeAzureGitClient(config.AzureGitConfig)
	}

	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		u := r.URL.Path[1:]
		var configName string
		if slash := strings.IndexByte(u, '/'); slash != -1 {
			configName = u[:slash]
		} else {
			configName = u
		}
		item, err := azureGitClient.GetItem(configName + ".yml")
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		configset, err := azureGitClient.DownloadConfig(item.URL)
		if err != nil {
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
			Name:     configName,
			Profiles: []string{"default"},
			Version:  item.CommitID,
			PropertySources: []PropertySource{
				PropertySource{
					Name:   configName + ".yml",
					Source: flattened,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		if err := json.NewEncoder(w).Encode(cloudConfigAnswer); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	})
	log.Println("started in", time.Since(start), "and listening at", listen)
	if err := http.ListenAndServe(listen, &mux); err != nil {
		panic(err)
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
