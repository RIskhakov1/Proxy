package main 

import (
	"crypto/sha256"
	"os"
	"log"
	"net/url"
	"net/http"
	"fmt"
	"time"
	"strconv"
	"strings"
	"io/ioutil"
	"io"
	"math/rand"
	"sync"
	"encoding/json"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type taskContext struct {
	Timestamp 	string
	RandStr   	string
	RemoteAddress 	string
	Key       	string
	Hash      	string

}

var taskStorage = struct {
	mut sync.RWMutex
	m map[string]taskContext
}{m: make(map[string]taskContext)}

func SaveTask(timestamp string, c taskContext) {
	taskStorage.mut.RLock()
	taskStorage.m[timestamp] = c
	taskStorage.mut.RUnlock()
}

func DeleteTask(timestamp string) {
	taskStorage.mut.RLock()
	delete(taskStorage.m, timestamp)
	taskStorage.mut.RUnlock()
}

var cookieStorage = struct {
	mut sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

func SaveCookie(hash string, remote_addr string) {
        cookieStorage.mut.RLock()
        cookieStorage.m[hash] = remote_addr
        cookieStorage.mut.RUnlock()
}


const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}


func CreateTask(c echo.Context) taskContext {
	time := strconv.FormatInt(time.Now().UnixNano(), 10)
	str := RandStringBytes(20)
	task := taskContext{Timestamp: time,
		RandStr: str,
		RemoteAddress: c.Request().RemoteAddr}
	SaveTask(time, task)
	return task
}

func ServeHTML(task taskContext) (string, error) {
	templateHTML, err := ioutil.ReadFile("index.html")
        if err != nil {
        	return "", err
        }
        processedHTML := strings.Replace(string(templateHTML), "{{.Timestamp}}", fmt.Sprintf("%q", task.Timestamp), 1)
        processedHTML = strings.Replace(processedHTML, "{{.RandStr}}", fmt.Sprintf("%q", task.RandStr), 1)
	processedHTML = strings.Replace(processedHTML, "{{.RemoteAddress}}", fmt.Sprintf("%q", task.RemoteAddress), 1)
	return processedHTML, nil
}

func ParseSolution(c echo.Context) (taskContext, error) {
	b, _ := io.ReadAll(c.Request().Body)
	var solution taskContext
	if err := json.Unmarshal(b, &solution); err != nil {
		log.Println(err.Error())
		return solution, err
	}
	return solution, nil
}

func CheckSolution(s taskContext) bool {
	if taskStorage.m[s.Timestamp].RandStr != s.RandStr || taskStorage.m[s.Timestamp].RemoteAddress != s.RemoteAddress {
		log.Println("Got incorrect task's context")
		DeleteTask(s.Timestamp)
		return false
	}

	h := sha256.New()
	h.Write([]byte(s.Key + s.Timestamp + s.RandStr + s.RemoteAddress))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	if hash != s.Hash {
		log.Println("Got incorrect task's solution")
		DeleteTask(s.Timestamp)
		return false
	}

	if hash[:3] != "000" {
		log.Println("Got incorrect task's solution")
		DeleteTask(s.Timestamp)
		return false
	}
	return true
}

func ManageCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		_, err := c.Cookie("sessionID")
		if err != nil {
			if c.Request().Body == nil || c.Request().ContentLength == 0 {
				task := CreateTask(c)
				page, er := ServeHTML(task)
				if er != nil {
					return c.String(500, "Something went wrong, try again")
				}
				log.Println("task is given")
				c.Request().Close = true
				return c.HTML(http.StatusOK, page)
			}
			log.Println("body isnt empty, starting parsing")
			s, err := ParseSolution(c)
			if err != nil {
				return c.String(http.StatusUnauthorized, "Got incorrect solution")
			}

			if !CheckSolution(s) {
				return c.String(http.StatusUnauthorized, "Got incorrect solution")
			}
			log.Println("Creating new cookie")
			cookie := http.Cookie{
				Name:	  "sessionID",
				Value:	  s.Hash,
				Secure:	  true,
				HttpOnly: true,
				Expires: time.Now().Add(24 * time.Hour),
			}
			SaveCookie(s.Hash, c.Request().RemoteAddr)
			c.SetCookie(&cookie)
			log.Println(s.Hash)
			return c.String(http.StatusOK, "Set new cookie")
		}
		log.Println("Checking if cookie exists")
		cookie, err := c.Cookie("sessionID")
		if cookieStorage.m[cookie.Value] != c.Request().RemoteAddr {
			return c.String(http.StatusUnauthorized, "Incorrect cookie")
		}
		return next(c)
	}
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/", func (c echo.Context) error {
		return c.String(http.StatusOK, "fucking /")
	})

	upstream_url := os.Args[1]
	HeaderSet := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Request().Host = upstream_url
			return next(c)
		}
	}
	url, err := url.Parse(fmt.Sprintf("https://%s", upstream_url))
	if err != nil {
		e.Logger.Fatal(err)
	}
	targets := []*middleware.ProxyTarget{
		{
			URL: url,
		},
	}
	e.Use(HeaderSet)
	e.Use(ManageCookie)
	e.Use(middleware.Proxy(middleware.NewRoundRobinBalancer(targets)))

	er := e.Start(":8080")
	//er := e.StartTLS(":443", "path_to_cert.pem", "path_to_privkey.pem")
        if er != nil {
                log.Fatal(er)
        }

}
