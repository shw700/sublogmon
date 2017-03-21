package main

import "fmt"
import "log"
import "os"
import "regexp"
import "strings"
import "strconv"
import "io/ioutil"
import "encoding/json"
import "flag"
import "path/filepath"
import "time"

import fsnotify "gopkg.in/fsnotify.v1"

var colorsMap = map[string]string{
	"ANSI_COLOR_RED":      "\033[0;31m",
	"ANSI_COLOR_RED_BOLD": "\033[1;31m",
	"ANSI_COLOR_GREEN":    "\033[0;32m",
	"ANSI_COLOR_YELLOW":   "\033[0;33m",
	"ANSI_COLOR_RESET":    "\033[0m",
}

const AUDIT_LOG_FILE = "/var/log/audit/audit.log"

const BUFSIZE = 4096

type LogFunc func(string) string

type LogFunction struct {
	FuncName string
	Func     LogFunc
}

type LogFilter struct {
	ID         string
	Regexp     string
	Fields     []string
	OutputStr  string
	OutputAttr string
	Severity string
	Regcomp    *regexp.Regexp
}

type LogAuditFile struct {
	Description string
	SourceName  string
	PathName    string
	Filters     []LogFilter
	f           *os.File
	Backlog     string
}

type LogSuppression struct {
        Description string
        Metadata map[string]string
}

var AuditLogs []LogAuditFile
var Suppressions []LogSuppression

var (
	LogFunctions = []LogFunction{
		{FuncName: "getscname", Func: getSyscallByNumber}}
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
			outstr = AuditLogs[logIndex].Filters[filterIndex].OutputAttr + outstr + colorsMap["ANSI_COLOR_RESET"]
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

var progName string

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: "+progName+" [-h/-help] [-d/-debug] [-c/-config json_config] [-s/-suppress json_config]     where")
	fmt.Fprintln(os.Stderr, "  -c / -config:     specifies a custom json config file (\"sublogmon.json\" by default),")
	fmt.Fprintln(os.Stderr, "  -s / -suppress:   specifies a custom log suppression file (\"suppressions.json\" by default),")
	fmt.Fprintln(os.Stderr, "  -d / -debug:      dumps additional debug information to stderr,")
	fmt.Fprintln(os.Stderr, "  -h / -help:       display this help message,")
}

func main() {
	progName = os.Args[0]

	var conffile = flag.String("conf", "sublogmon.json", "Specify json config file")
	var supfile = flag.String("suppress", "suppressions.json", "Specify json config file")
	flag.StringVar(conffile, "c", "sublogmon.json", "Specify json config file")
	flag.StringVar(supfile, "s", "suppressions.json", "Specify json config file")
	var debug = flag.Bool("debug", false, "Turn on debug mode")
	flag.BoolVar(debug, "d", false, "Turn on debug mode")

	flag.Usage = usage
	flag.Parse()

	var args = flag.Args()

	if len(args) > 0 {
		flag.Usage()
		os.Exit(-1)
	}

	jfile, err := ioutil.ReadFile(*conffile)

	if err != nil {
		log.Fatal("Error opening json file: ", err)
		os.Exit(-1)
	}

	err = json.Unmarshal(jfile, &AuditLogs)

	if err != nil {
		log.Fatal("Error decoding json data from config file: ", err)
		os.Exit(-1)
	}

	jfile, err = ioutil.ReadFile(*supfile)

	if err != nil {
		fmt.Println("Warning: no suppressions file was found!")
	} else {

		err = json.Unmarshal(jfile, &Suppressions)

		if err != nil {
			log.Fatal("Error decoding json data from suppressions file: ", err)
			os.Exit(-1)
		}

		if *debug {
			fmt.Fprintf(os.Stderr, "Read a total of %d suppressions from config\n", len(Suppressions))
		}

	}

	if *debug {
		fmt.Fprintf(os.Stderr, "There are %d log file entries\n", len(AuditLogs))
	}

	for i := 0; i < len(AuditLogs); i++ {

		if *debug {
			fmt.Fprintf(os.Stderr, "{%d} Description = |%s|, Pathname = |%s| -> %d filters\n", i, AuditLogs[i].Description, AuditLogs[i].PathName, len(AuditLogs[i].Filters))
		}

		for j := 0; j < len(AuditLogs[i].Filters); j++ {
			fil := &(AuditLogs[i].Filters[j])
			outStr := "*" + fil.OutputAttr + "*"
			attr, ok := colorsMap[fil.OutputAttr]

			if ok {
				fil.OutputAttr = attr
			} else {
				outStr = attr
			}

			if *debug {
				fmt.Fprintf(os.Stderr, "   [%d] Regexp = %s\n", j+1, fil.Regexp)
				fmt.Fprintf(os.Stderr, "   [%d] nfields = %d : %v\n", j+1, len(fil.Fields), fil.Fields)
				fmt.Fprintf(os.Stderr, "   [%d] OutputStr = %s, OutputAttr = %s\n", j+1, fil.OutputStr, outStr)
			}

		}
	}

/*		fmt.Println("Attempting test...")
		testRegexp(2, 1, "Mar  8 22:09:55 subgraph oz-daemon[23280]: 2017/03/08 22:09:55 [spotify] (stderr) E [FATAL] Seccomp filter compile failed: /var/lib/oz/cells.d/spotify-whitelist.seccomp:18: unexpected end of line")
		fmt.Println("Exiting.")
		os.Exit(0) */


	dbo, err := newDbusObject()
	if err != nil {
		log.Fatal("Error connecting to SystemBus: %v", err)
	}

	if os.Getuid() > 0 {
		fmt.Println("Warning: this program probably won't run unless you execute it as root.")
	}

	parentDirs := make(map[string]bool)

	for i := 0; i < len(AuditLogs); i++ {
		f, err := os.OpenFile(AuditLogs[i].PathName, os.O_RDONLY, 0666)

		if err != nil {
			log.Fatal("Error opening log file for ", AuditLogs[i].Description, ": ", err)
		}

		fi, err := f.Stat()

		if err != nil {
			log.Fatal("Could not call stat on log file: ", err)
		}

		pdir := filepath.Dir(AuditLogs[i].PathName)

		if _, ok := parentDirs[pdir]; ok {
		} else {
			parentDirs[pdir] = true
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

	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		log.Fatal("Could not set up new watcher: ", err)
	}

	defer watcher.Close()

	for i := 0; i < len(AuditLogs); i++ {

		if *debug {
			fmt.Println("Adding inotify watcher for service:", AuditLogs[i].Description)
		}
		//	err = watcher.AddWatch(AuditLogs[i].PathName, inotify.IN_MODIFY)
		//	err = watcher.AddWatch(AuditLogs[i].PathName, inotify.IN_ALL_EVENTS)
		err = watcher.Add(AuditLogs[i].PathName)

		if err != nil {
			log.Fatal("Could not set up watcher on log file: ", err)
		}

	}


	for dname, _ := range parentDirs {

		if *debug {
			fmt.Println("Adding inotify watcher for parent directory events:", dname)
		}

		err = watcher.Add(dname)

		if err != nil {
			log.Fatal("Could not set up watcher on log file directory: ", err)
		}

	}

	fmt.Printf("Done loading, going into I/O loop.\n")

	dbuf := make([]byte, BUFSIZE)
	last_buf := ""
	last_repeat := 0

	for {

		select {
		case ev := <-watcher.Events:
			// fmt.Println("watcher event")
			// log.Println("event: ", ev)
			// fmt.Printf("mask was %x\n", ev.Mask)

			// with fsnotify.v1, all possible events notifications should be modifications
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
				fmt.Printf("Received unexpected notification event type (%v)... ignoring.\n", ev.Op)
				continue
			}

			// fmt.Println("caught event operation: ", ev.Op, " / hmm: ", ev.Name)

			i := 0

			for i < len(AuditLogs) {

				if AuditLogs[i].PathName == ev.Name {
					// fmt.Printf("comparison: |%s| vs |%s|\n", ev.Name, AuditLogs[i].PathName)
					break
				}

				i++
			}

			if i == len(AuditLogs) {
				idir := filepath.Dir(ev.Name)

				_, ok := parentDirs[idir]

				if !ok {
					log.Fatal("Unexpected error occurred: received inotify event for unknown filename \"", ev.Name, "\"")
				}

				continue
			}

			if ev.Op & fsnotify.Create == fsnotify.Create {

				if *debug {
					fmt.Println("Looks like a monitored file just rolled over: ", ev.Name)
				}

				AuditLogs[i].f.Close()

				AuditLogs[i].f, err = os.OpenFile(AuditLogs[i].PathName, os.O_RDONLY, 0666)

				if err != nil {
					log.Fatal("Error re-opening rolled log file ", AuditLogs[i].PathName, ": ", err)
				}

				// XXX: Right now we're subject to what's almost like a minor race condition.
				// We have no way of knowing if the newly created file has been created afresh or is the
				// product of a renaming. The desired behavior for a "new" file is to read it from the
				// beginning. The desired behavior, on the other hand, for a renamed file is to seek
				// to the end and start reading from there.
				//
				// Unfortunately, it is likely that the process creating and writing to the logfile
				// will have completed both operations before the log monitor receives the inotify event.
				// In that case, sublogmon will attempt to seek to the end of the "created" file but
				// will do so after the initial contents of the file have been written by its owner -
				// thereby missing the first batch of data.
				//
				// The solution is probably to use a better inotify package.

				_, err := AuditLogs[i].f.Seek(0, os.SEEK_END)

				if err != nil {
					fmt.Println("Seek failed in rolled logfile: ", err)
				}

			}

			if ev.Op & fsnotify.Write != fsnotify.Write {
				continue
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

					/* for k := 0; k < len(AuditLogs[i].Filters[j].Fields); k++ {
						fstr := AuditLogs[i].Filters[j].Fields[k]
						fmt.Printf("Extracting field: %s = %s\n", fstr, rmap[fstr])
					} */

					outstr := formatOutput(AuditLogs[i].Filters[j].OutputStr, rmap)

					if len(outstr) == 0 {
						fmt.Println("*** Filter condition was matched but no output string was generated")
					} else {
						alertstr := outstr
						if len(AuditLogs[i].Filters[j].OutputAttr) > 0 {
							outstr = AuditLogs[i].Filters[j].OutputAttr + outstr + colorsMap["ANSI_COLOR_RESET"]
						}

						now := time.Now().UnixNano()

						if last_buf == outstr {
							last_repeat++
							fmt.Print("\r", colorsMap["ANSI_COLOR_GREEN"], "--- Suppressed identical output line ", last_repeat, " times.", colorsMap["ANSI_COLOR_RESET"])
							dbo.alertObj(AuditLogs[i].Filters[j].ID, AuditLogs[i].Filters[j].Severity, now, alertstr, curLine, rmap)
							break
						} else {

							if last_repeat > 0 {
								fmt.Println("")
							}

							last_buf = outstr
							last_repeat = 0

						}

						fmt.Println("* ", outstr)
						dbo.alertObj(AuditLogs[i].Filters[j].ID, AuditLogs[i].Filters[j].Severity, now, alertstr, curLine, rmap)
						break
					}

				}

			}

		case err := <-watcher.Errors:
			log.Println("error: ", err)
		}

	}

}
