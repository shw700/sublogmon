package main

import "fmt"
import "log"
import "os"
import "regexp"
import "strings"
import "strconv"
import "golang.org/x/exp/inotify"

const ANSI_COLOR_RED = "\033[0;31m"
const ANSI_COLOR_RED_BOLD = "\033[1;31m"
const ANSI_COLOR_YELLOW = "\033[0;33m"
const ANSI_COLOR_RESET = "\033[0m"

const AUDIT_LOG_FILE = "/var/log/audit/audit.log"

const BUFSIZE = 4096

type LogFunc func(string) string

type LogFunction struct {
	FuncName string
	Func     LogFunc
}

type LogFilter struct {
	Regexp     string
	Fields     []string
	OutputStr  string
	OutputAttr string
	Regcomp    *regexp.Regexp
}

type LogAuditFile struct {
	Desc     string
	PathName string
	Filters  []LogFilter
	f        *os.File
	Backlog  string
}

var (
	LogFunctions = []LogFunction{
		{FuncName: "getscname", Func: getSyscallByNumber}}
)

var (
	AuditLogs = []LogAuditFile{
		/*0*/ {Desc: "auditd events", PathName: "/var/log/audit/audit.log", Filters: []LogFilter{
			{Regexp: "^type=SECCOMP msg=.+exe=\"(?P<exename>.+)\".+arch=(?P<arch>.+) syscall=(?P<syscall>[0-9]+)",
				Fields:     []string{"exename", "arch", "syscall"},
				OutputStr:  "SECCOMP violation detected when application {exename} attempted to call syscall ${syscall}:getscname:",
				OutputAttr: ANSI_COLOR_RED_BOLD},
			{Regexp: "^type=AVC.+apparmor=\"DENIED\" operation=\"(?P<operation>.+?)\".+profile=\"(?P<profile>.+?)\".+name=\"(?P<target>.+?)\".+comm=\"(?P<application>.+?)\".+",
				Fields:     []string{"operation", "application", "target"},
				OutputStr:  "AppArmor violation of profile {profile} detected from {application} attempting {operation} on {target}",
				OutputAttr: ANSI_COLOR_RED_BOLD}}},
		/*1*/ {Desc: "oz daemon log", PathName: "/var/log/oz-daemon.log", Filters: []LogFilter{
			{Regexp: ".+oz-daemon\\[.+\\[(?P<application>.+)\\].+\\[FATAL\\] (?P<errmsg>.+)",
				Fields:     []string{"application", "errmsg"},
				OutputStr:  "Fatal oz-daemon condition encountered in {application}: {errmsg}",
				OutputAttr: ANSI_COLOR_RED_BOLD}}},
		/*2*/ {Desc: "tor daemon log", PathName: "/var/log/tor/log", Filters: []LogFilter{
			{Regexp: ".+behind the time published.+\\((?P<utctime>.+)\\).+Tor needs an accurate clock.+Please check your time.+",
				Fields:     []string{"utctime"},
				OutputStr:  "FATAL: TOR will not work unless you update your system clock to: {utctime}",
				OutputAttr: ANSI_COLOR_RED_BOLD},
			{Regexp: ".+\\[warn\\] (?P<warning>.+)",
				Fields:     []string{"warning"},
				OutputStr:  "TOR WARNING: {warning}",
				OutputAttr: ANSI_COLOR_RED}}},
		/*3*/ {Desc: "kernel and dmesg buffer", PathName: "/var/log/kern.log", Filters: []LogFilter{
			{Regexp: ".+kernel:.+PAX: terminating task: (?P<application>.+):[0-9]+,.+",
				Fields:     []string{"application"},
				OutputStr:  "PAX terminated process: {application}",
				OutputAttr: ANSI_COLOR_RED_BOLD},
			{Regexp: ".+kernel:.+grsec: denied (?P<action>.+?) .+ by (?P<application>.+?)\\[.+",
				Fields:     []string{"action", "application"},
				OutputStr:  "grsec denied operation {action} to application {application}",
				OutputAttr: ANSI_COLOR_YELLOW},
			{Regexp: ".+kernel:.+grsec: (?P<grsecmsg>.+)",
				Fields:    []string{"grsecmsg"},
				OutputStr: "grsec msg: {grsecmsg}"}}},
		/*4*/ {Desc: "daemon log", PathName: "/var/log/daemon.log", Filters: []LogFilter{
			{Regexp: ".+roflcoptor.+DENY: \\[(?P<application>.+)\\].+",
				Fields:     []string{"application"},
				OutputStr:  "roflcoptor denied unauthorized Tor control port access by {application}",
				OutputAttr: ANSI_COLOR_RED}}},

		/* 5*/ {Desc: "syslog", PathName: "/var/log/syslog", Filters: []LogFilter{
			{Regexp: ".+fw-daemon.+DENY\\|(?P<host>.+?):(?P<port>\\d+?) \\((?P<app>.+?) -\\> (?P<ip>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+?):[0-9]+\\)", //\\)",
				Fields:     []string{"host", "port"}, // , "app", "ip"},
				OutputStr:  "Subgraph Firewall denied {app} connect attempt to {host} ({ip}) on port {port}",
				OutputAttr: ANSI_COLOR_RED}}}}
)

func getSyscallByNumber(data string) string {
	scno, err := strconv.Atoi(data)

	if err != nil {
		fmt.Printf("Error: syscall \"%s\" does not appear to be a valid number.\n", data)
		return ""
	}

	for key, val := range Syscalls {

		if val == scno {
			return key
		}

	}

	fmt.Printf("Error: syscall \"%s\" does not appear to be a valid number.\n", data)
	return ""
}

func testRegexp(logIndex int, filterIndex int, expression string) {

	restr := AuditLogs[logIndex].Filters[filterIndex].Regexp
	re := regexp.MustCompile(restr)

	fmt.Println("REGEXP: ", restr)
	fmt.Println("Being matched against: ", expression)

	match := re.FindStringSubmatch(expression)

	if match == nil {
		fmt.Println("There was no match.")
		return
	}

	rmap := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 {
			rmap[name] = match[i]
		}
	}

	for i := 0; i < len(AuditLogs[logIndex].Filters[filterIndex].Fields); i++ {
		fstr := AuditLogs[logIndex].Filters[filterIndex].Fields[i]
		fmt.Printf("Extracting field: %s = \"%s\"\n", fstr, rmap[fstr])
	}

	outstr := formatOutput(AuditLogs[logIndex].Filters[filterIndex].OutputStr, rmap)

	if len(outstr) == 0 {
		fmt.Println("*** No output string was returned.")
	} else {

		if len(AuditLogs[logIndex].Filters[filterIndex].OutputAttr) > 0 {
			outstr = AuditLogs[logIndex].Filters[filterIndex].OutputAttr + outstr + ANSI_COLOR_RESET
		}

		fmt.Println("OUTPUT: ", outstr)
	}

}

func formatOutput(src string, strMap map[string]string) string {
	retstr := src

	for key, val := range strMap {
		replStr := "{" + key + "}"

		sInd := strings.Index(retstr, replStr)

		for sInd > -1 {
			fInd := sInd
			lInd := sInd + len(replStr)
			replaced := val

			if fInd > 0 && retstr[fInd-1] == '$' {
				fInd--

				afterBrace := retstr[lInd:]

				if len(afterBrace) < 2 || afterBrace[0] != ':' {
					fmt.Printf("Error in formatting rule: \"%s\"\n", src)
					return ""
				}

				endFuncInd := strings.Index(retstr[lInd+1:], ":")

				if endFuncInd <= 0 {
					fmt.Printf("Error in formatting rule: \"%s\"\n", src)
					return ""
				}

				custFuncName := retstr[lInd+1 : lInd+1+endFuncInd]

				lInd += endFuncInd + 2

				for i := 0; i < len(LogFunctions); i++ {

					if LogFunctions[i].FuncName == custFuncName {
						replaced = LogFunctions[i].Func(replaced)

						if len(replaced) == 0 {
							replaced = val
							break
						}

					}

				}

			}

			retstr = retstr[0:fInd] + replaced + retstr[lInd:]
			sInd = strings.Index(retstr, replStr)
		}

	}

	return retstr
}

func main() {

	/*
		fmt.Println("Attempting test...")
		testRegexp(1, 0, "Jul 21 18:58:32 subgraph oz-daemon[1281]: 2016/07/21 18:58:32 [gedit] (stderr) E [FATAL] Error (exec): no such file or directory /usr/bin-oz/gedit")
		fmt.Println("Exiting.")
		os.Exit(0)
	*/

	dbo, err := newDbusObject()
	if err != nil {
		log.Fatal("Error connecting to SystemBus: %v", err)
	}

	if os.Getuid() > 0 {
		fmt.Println("Warning: this program probably won't run unless you execute it as root.")
	}

	for i := 0; i < len(AuditLogs); i++ {
		f, err := os.OpenFile(AuditLogs[i].PathName, os.O_RDONLY, 0666)

		if err != nil {
			log.Fatal("Error opening log file for ", AuditLogs[i].Desc, ": ", err)
		}

		fi, err := f.Stat()

		if err != nil {
			log.Fatal("Could not call stat on log file: ", err)
		}

		// fmt.Printf("total log file size for %s  is %d\n", AuditLogs[i].PathName, fi.Size())

		ret, err := f.Seek(0, os.SEEK_END)

		if err != nil {
			log.Fatal("Unexpected problem occurred while attempting to skip to end of log file: ", err)
		}

		if ret != fi.Size() {
			log.Fatal("Unexpected problem occurred when attempting to skip to end of log file")
		}

		AuditLogs[i].f = f

		for j := 0; j < len(AuditLogs[i].Filters); j++ {
			AuditLogs[i].Filters[j].Regcomp = regexp.MustCompile(AuditLogs[i].Filters[j].Regexp)
		}

	}

	watcher, err := inotify.NewWatcher()

	if err != nil {
		log.Fatal("Could not set up new watcher: ", err)
	}

	for i := 0; i < len(AuditLogs); i++ {
		fmt.Println("Adding inotify watcher for service:", AuditLogs[i].Desc)
		//		err = watcher.AddWatch(AuditLogs[i].PathName, inotify.IN_MODIFY)
		err = watcher.AddWatch(AuditLogs[i].PathName, inotify.IN_ALL_EVENTS)

		if err != nil {
			log.Fatal("Could not set up watcher on log file: ", err)
		}

	}

	fmt.Printf("Done loading, going into I/O loop.\n")

	dbuf := make([]byte, BUFSIZE)

	for {

		select {
		case ev := <-watcher.Event:
			// fmt.Println("watcher event")
			// log.Println("event: ", ev)
			// fmt.Printf("mask was %x\n", ev.Mask)

			switch ev.Mask {
			case inotify.IN_ACCESS:
				fallthrough
			case inotify.IN_CLOSE_WRITE:
				fallthrough
			case inotify.IN_CLOSE_NOWRITE:
				fallthrough
			case inotify.IN_OPEN:
				//fmt.Println("caught an event of no importance!")
				continue
			}

			//Important: IN_MOVE_SELF, IN_ATTRIB(delete)

			if ev.Mask&inotify.IN_MODIFY != inotify.IN_MODIFY {
				fmt.Printf("Received unexpected notification event type (%x)... ignoring.\n", ev.Mask)
				continue
			}

			i := 0

			for i < len(AuditLogs) {

				if AuditLogs[i].PathName == ev.Name {
					//						fmt.Printf("comparison: |%s| vs |%s|\n", ev.Name, AuditLogs[i].PathName)
					break
				}

				i++
			}

			if i == len(AuditLogs) {
				log.Fatal("Unexpected error occurred: received inotify event for unknown filename \"", ev.Name, "\"")
			}

			os.Getuid()
			nread, err := AuditLogs[i].f.Read(dbuf)
			os.Getpid()

			if err != nil && nread != 0 {
				log.Fatal("Error reading new data from log file: ", err)
			}

			if nread == 0 {
				// fmt.Printf("Reached EOF for %s; attempting to ignore.\n", AuditLogs[i].PathName)
				_, err := AuditLogs[i].f.Seek(0, os.SEEK_END)

				if err != nil {
					fmt.Println("Seek failed: ", err)
				}

				continue
			}

			//fmt.Printf("ended up reading %d bytes from log\n", nread)

			sbuf := string(dbuf[:nread])
			AuditLogs[i].Backlog += sbuf

			nIndex := strings.Index(AuditLogs[i].Backlog, "\n")

			if nIndex == -1 {
				continue
			}

			for nIndex != -1 {
				curLine := AuditLogs[i].Backlog[0:nIndex]
				//fmt.Printf("current line = |%s|\n", curLine)
				AuditLogs[i].Backlog = AuditLogs[i].Backlog[nIndex+1:]
				nIndex = strings.Index(AuditLogs[i].Backlog, "\n")

				for j := 0; j < len(AuditLogs[i].Filters); j++ {
					// fmt.Printf("trying regex filter %d: %s\n", j, AuditLogs[i].Filters[j].Regexp)
					// fmt.Printf("AGAINST: %s\n", curLine)

					match := AuditLogs[i].Filters[j].Regcomp.FindStringSubmatch(curLine)

					if match == nil {
						//							fmt.Printf("%sdid not match, continuing%s\n", ANSI_COLOR_RED_BOLD, ANSI_COLOR_RESET)
						continue
					}

					rmap := make(map[string]string)

					for k, name := range AuditLogs[i].Filters[j].Regcomp.SubexpNames() {

						if k != 0 {
							rmap[name] = match[k]
						}

					}

					/*for k := 0; k < len(AuditLogs[i].Filters[j].Fields); k++ {
						fstr := AuditLogs[i].Filters[j].Fields[k]
						fmt.Printf("Extracting field: %s = %s\n", fstr, rmap[fstr])
					} */

					outstr := formatOutput(AuditLogs[i].Filters[j].OutputStr, rmap)

					if len(outstr) == 0 {
						fmt.Println("*** Filter condition was matched but no output string was generated")
					} else {
						alertstr := outstr
						if len(AuditLogs[i].Filters[j].OutputAttr) > 0 {
							outstr = AuditLogs[i].Filters[j].OutputAttr + outstr + ANSI_COLOR_RESET
						}

						fmt.Println("* ", outstr)
						dbo.alert(alertstr)
					}

				}

			}

		case err := <-watcher.Error:
			log.Println("error: ", err)
		}

	}

}
