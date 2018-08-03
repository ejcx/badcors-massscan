package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// hw is for scanning a site for http headers.

type Scan struct {
	RequestTimeout time.Duration
}

type SiteResult struct {
	Vulnerable  bool
	HTTPResult  string
	HTTPSResult string
	Host        string
}

type ConfigFile struct {
	Sites   []string `yaml:"sites"`
	Workers int      `yaml:"workers"`
}

func main() {
	config := flag.String("config", "", "The hw config file")
	flag.Parse()

	var c ConfigFile
	if *config == "" {
		log.Fatalf("Config file is required")
	}
	configBytes, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("Could not read config file: %s", err)
	}

	err = yaml.Unmarshal([]byte(configBytes), &c)
	if err != nil {
		log.Fatalf("Could not unmarshal yaml config file: %s", err)
	}

	s := make(chan string, c.Workers)

	// Start reading from files.
	go func() {
		for _, fname := range c.Sites {
			f, err := os.Open(fname)
			if err != nil {
				log.Fatalf("Could not open site file: %s", err)
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				s <- scanner.Text()
			}
		}
		close(s)
	}()

	scan := &Scan{
		RequestTimeout: time.Second * 10,
	}
	var wg sync.WaitGroup
	// Start the workers.
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		//b := i
		go func() {
			for site := range s {
				scan.Do(site)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func (s *Scan) Do(site string) {

	httpVuln, httpR := s.ScanSite("http", site)
	httpsVuln, httpsR := s.ScanSite("https", site)

	b, err := json.Marshal(SiteResult{
		Vulnerable:  httpVuln || httpsVuln,
		HTTPResult:  httpR,
		HTTPSResult: httpsR,
		Host:        site,
	})
	if err != nil {
		log.Printf("Could not marshal site: %s", err)
		return
	}
	fmt.Println(string(b))
}

func (s *Scan) ScanSite(prefix, site string) (bool, string) {
	siteURL := fmt.Sprintf("%s://%s", prefix, site)
	fullURL := fmt.Sprintf("%s://%s.%s", prefix, site, ".myevilsite.com")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout: s.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Set("Origin", fullURL)
			return nil
		},
		Transport: tr,
	}

	httpReq, err := http.NewRequest("GET", siteURL, nil)
	if err != nil {
		log.Printf("Error creating request: %s", err)
		return false, ""
	}
	httpReq.Header.Set("Origin", fullURL)
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Error client doing: %s", err)
		return false, ""
	}
	vulnerable := checkRespForCors(resp, site)
	r, _ := json.Marshal(resp)
	if vulnerable {
		return true, string(r)
	}
	return false, string(r)
}

func checkRespForCors(r *http.Response, site string) bool {
	var hasVulnACAO bool
	var hasVulnACAC bool
	for k, v := range r.Header {
		// Take the first one
		val := v[0]
		if strings.ToLower(k) == "access-control-allow-origin" {
			hasVulnACAO = strings.Contains(strings.ToLower(val), "myevilsite.com")
		}
		if strings.ToLower(k) == "access-control-allow-credentials" {
			hasVulnACAC = strings.Contains(strings.ToLower(val), "true")
		}
	}
	return hasVulnACAO && hasVulnACAC
}
