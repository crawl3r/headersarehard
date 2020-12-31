package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

/*
	Aim: make the output easy to parse/load/grep

	Output (tbc):
		[HTTP] Good:
		- Name
		- Key: Value

		[HTTPS] Good:
		- Name
		- Key: value

		[HTTP] Bad:
		- Name
		- Key: Value

		[HTTPS] Bad:
		- Name
		- Key: Value
*/

type Headers struct {
	Headers []Header
}

type Header struct {
	Name string
	Data HeaderData
}

type HeaderData struct {
	Key    string
	Value  string
	Search string
}

type ReportHeaders struct {
	CurrentHeader     Header
	RecommendedHeader string
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	url, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	if len(url) == 0 {
		fmt.Println("Pipe in a target host please...")
		fmt.Println("\techo \"target.com\" | ./headersarehard")
		return
	}

	var headerJsonFileFlag string
	flag.StringVar(&headerJsonFileFlag, "h", "", "Header JSON file for use with regex checks")
	quietModeFlag := flag.Bool("q", false, "Only output the headers (ez grep mode)")
	flag.Parse()
	quietMode := *quietModeFlag

	if !quietMode {
		banner()
	}

	url = strings.ReplaceAll(url, "\n", "")
	url = strings.ReplaceAll(url, "http://", "")
	url = strings.ReplaceAll(url, "https://", "")

	if _, err := os.Stat(headerJsonFileFlag); os.IsNotExist(err) {
		log.Fatalf("Could not find headerJSONfile at: %s. (err: %s)", headerJsonFileFlag, err)
		os.Exit(99)
	}

	jsonFile, _ := os.Open(headerJsonFileFlag)
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var secsyHeaders Headers
	json.Unmarshal(byteValue, &secsyHeaders)

	verboseHeaders := []string{
		"Server",
		"X-AspNetMvc-Version",
		"X-AspNet-Version",
		"X-Powered-By",
	}

	httpHeaders := makeRequest(url, false, quietMode)
	httpsHeaders := makeRequest(url, true, quietMode)

	httpSecTag := "\t"
	httpsSecTag := "\t"
	httpVerbTag := "\t"
	httpsVerbTag := "\t"

	if quietMode {
		httpSecTag = "[HTTP]{S} "
		httpsSecTag = "[HTTPS]{S} "
		httpVerbTag = "[HTTP]{V} "
		httpsVerbTag = "[HTTPS]{V} "
	}

	// check http security headers
	if httpHeaders != nil {
		if !quietMode {
			fmt.Println("")
			fmt.Println("HTTP SECURITY HEADERS")
		}

		httpSafeSecHeaders, httpRecommendedSecHeaders := parseSecurityHeaders(httpHeaders, &secsyHeaders)

		if !quietMode {
			fmt.Println("Good: ")
			for v, _ := range httpSafeSecHeaders {
				fmt.Println(httpSecTag, v)
			}
			fmt.Println("")
		}

		if !quietMode {
			fmt.Println("Missing/Bad: ")
		}

		for _, h := range httpRecommendedSecHeaders {
			fmt.Println(httpSecTag, h.CurrentHeader.Data.Key)
		}

		if !quietMode {
			fmt.Println("")
		}
	}

	// check https security headers

	if httpsHeaders != nil {
		if !quietMode {
			fmt.Println("HTTPS SECURITY HEADERS")
		}

		httpsSafeSecHeaders, httpsRecommendedSecHeaders := parseSecurityHeaders(httpsHeaders, &secsyHeaders)

		if !quietMode {
			fmt.Println("Good: ")
			for v, _ := range httpsSafeSecHeaders {
				fmt.Println(httpSecTag, v)
			}
			fmt.Println("")
		}

		if !quietMode {
			fmt.Println("Missing/Bad: ")
		}

		for _, h := range httpsRecommendedSecHeaders {
			fmt.Println(httpsSecTag, h.CurrentHeader.Data.Key)
		}

		if !quietMode {
			fmt.Println("")
		}
	}

	// check http verbose headers
	if httpHeaders != nil {
		if !quietMode {
			fmt.Println("HTTP VERBOSE HEADERS")
		}

		httpVerboseHeaders := parseVerboseHeaders(httpHeaders, verboseHeaders)

		for v, _ := range httpVerboseHeaders {
			fmt.Println(httpVerbTag, v)
		}

		if !quietMode {
			fmt.Println("")
		}
	}

	// check https verbose headers
	if httpsHeaders != nil {
		if !quietMode {
			fmt.Println("HTTPS VERBOSE HEADERS")
		}

		httpsVerboseHeaders := parseVerboseHeaders(httpsHeaders, verboseHeaders)

		for v, _ := range httpsVerboseHeaders {
			fmt.Println(httpsVerbTag, v)
		}

		if !quietMode {
			fmt.Println("")
		}
	}
}

func banner() {
	fmt.Println("---------------------------------------------------")
	fmt.Println("Headers are Hard, apparently")
	fmt.Println("List missing/bad security headers & verbose headers")
	fmt.Println("Run again with -q for ez grep!")
	fmt.Println("")
	fmt.Println("Missing/Bad Security headers:")
	fmt.Println("\"[HTTP]{S}\"")
	fmt.Println("\"[HTTPS]{S}\"")
	fmt.Println("Verbose headers:")
	fmt.Println("\"[HTTP]{V}\"")
	fmt.Println("\"[HTTPS]{V}\"")
	fmt.Println("---------------------------------------------------")
}

func makeRequest(url string, ssl bool, quietMode bool) http.Header {
	finalUrl := ""

	if ssl {
		finalUrl = "https://" + url
	} else {
		finalUrl = "http://" + url
	}

	if !quietMode {
		fmt.Println("Testing:", finalUrl)
	}
	resp, err := http.Get(finalUrl)
	if err != nil {
		if !quietMode {
			fmt.Println("[error] could not make request to:", finalUrl)
		}
		return nil
	}

	return resp.Header
}

// we want to return something like the following:
// 		Headers found [header and value]
// 		Headers missing [header & value & recommended value]

func parseSecurityHeaders(headers map[string][]string, targetHeaders *Headers) (map[string][]string, []ReportHeaders) {
	safeHeaders := map[string][]string{}
	recommendedHeaders := []ReportHeaders{}

	for _, th := range targetHeaders.Headers {
		// fmt.Println(th.Name)
		headerFound := false
		for k, v := range headers {
			if headerFound {
				break
			}
			// probably want to regex the header name incase of spelling etc??
			if th.Data.Key == k {
				headerFound = true
				for _, vv := range v {
					// fmt.Println("\t[?] Found: ", k, " value: ", v)

					matched, err := regexp.Match(th.Data.Search, []byte(vv))
					if err != nil {
						// fmt.Println("\t[!!!] Regex errored: ", err)
						continue
					}

					if matched {
						// fmt.Println("\t[+] Header: ", th.Name, " seems safe")
						// fmt.Println("")

						safeHeaders[k] = v
					} else {
						// fmt.Println("\t[-] Header: ", th.Name, " does not have the optimum value")
						// fmt.Println(vv)
						// fmt.Println("")

						newHeader := ReportHeaders{
							CurrentHeader:     th,
							RecommendedHeader: th.Data.Value,
						}
						recommendedHeaders = append(recommendedHeaders, newHeader)
					}
				}
			}
		}

		if !headerFound {
			// fmt.Println("\t[!!!] Header: ", th.Name, " was not found in the response")
			// fmt.Println("")

			newHeader := ReportHeaders{
				CurrentHeader:     th,
				RecommendedHeader: th.Data.Value,
			}
			recommendedHeaders = append(recommendedHeaders, newHeader)
		}
	}

	return safeHeaders, recommendedHeaders
}

func parseVerboseHeaders(headers map[string][]string, verboseHeaders []string) map[string][]string {
	toRemoveHeaders := map[string][]string{}

	for _, vh := range verboseHeaders {
		for k, v := range headers {
			// probably want to regex the header name incase of spelling etc??
			if vh == k {
				toRemoveHeaders[k] = v
				break
			}
		}
	}

	return toRemoveHeaders
}
