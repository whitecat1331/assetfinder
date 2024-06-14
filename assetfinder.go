package assetfinder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/whitecat1331/godevsuite"
)

const LOGPATH = "logs/assetfinder.log"

func AssetFinder(domains []string, subsOnly bool, logPath string) ([]string, error) {
	if logPath == "" {
		logPath = LOGPATH
	}
	var assetsFound []string
	allAssets := make(chan string)
	wgPool := new(sync.WaitGroup)
	slogger, f, err := godevsuite.SetupSLogger(logPath)
	if err != nil {
		fmt.Printf("Logger not setup\n%s\n%#T", err.Error(), err)
		return nil, err
	}
	defer f.Close()

	for _, domain := range domains {
		wgPool.Add(1)
		go assetFinder(allAssets, wgPool, domain, subsOnly, slogger)
	}

	go func() {
		wgPool.Wait()
		close(allAssets)
	}()

	for asset := range allAssets {
		assetsFound = append(assetsFound, asset)
	}

	return godevsuite.RemoveDuplicates(assetsFound), nil

}

// use go keyword with this function
func assetFinder(allAssets chan<- string, wgPool *sync.WaitGroup,
	domain string, subsOnly bool, slogger *godevsuite.SLogger) {
	defer wgPool.Done()

	assets := make(chan string)

	domains := strings.NewReader(domain)

	sources := []fetchFn{
		fetchCertSpotter,
		fetchHackerTarget,
		fetchThreatCrowd,
		fetchCrtSh,
		fetchFacebook,
		// fetchWayback, // A little too slow :(
		fetchVirusTotal,
		fetchFindSubDomains,
		fetchUrlscan,
		fetchBufferOverrun,
	}

	var wg sync.WaitGroup

	sc := bufio.NewScanner(domains)
	rl := newRateLimiter(time.Second)

	for sc.Scan() {
		domain := strings.ToLower(sc.Text())

		// call each of the source workers in a goroutine
		for _, source := range sources {
			wg.Add(1)
			fn := source

			go func() {
				defer wg.Done()

				rl.Block(fmt.Sprintf("%#v", fn))
				names, err := fn(domain)

				if err != nil {
					slogger.Error(fmt.Sprintf("err: %s\n", err))
					return
				}

				for _, n := range names {
					n = cleanDomain(n)
					if subsOnly && !strings.HasSuffix(n, domain) {
						continue
					}
					assets <- n
				}
			}()
		}
	}

	// close the output channel when all the workers are done
	go func() {
		wg.Wait()
		close(assets)
	}()

	for asset := range assets {
		allAssets <- asset
	}

}

type fetchFn func(string) ([]string, error)

func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	raw, err := io.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []byte{}, err
	}

	return raw, nil
}

func cleanDomain(d string) string {
	d = strings.ToLower(d)

	// no idea what this is, but we can't clean it ¯\_(ツ)_/¯
	if len(d) < 2 {
		return d
	}

	if d[0] == '*' || d[0] == '%' {
		d = d[1:]
	}

	if d[0] == '.' {
		d = d[1:]
	}

	return d

}

func fetchJSON(url string, wrapper interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)

	return dec.Decode(wrapper)
}
