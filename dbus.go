package main

import (
//	"fmt"
        "github.com/godbus/dbus"
)

type dbusObject struct {
        dbus.BusObject
}

type slmData struct {
	EventID string
	LogLevel string
	Timestamp int64
	LogLine string
	Metadata map[string]string
}

func newDbusObject() (*dbusObject, error) {
        conn, err := dbus.SystemBus()

        if err != nil {
                return nil, err
        }

        return &dbusObject{conn.Object("com.subgraph.EventNotifier", "/com/subgraph/EventNotifier")}, nil
}

func (ob *dbusObject) alertObj(id, level string, timestamp int64, line string, metadata map[string]string) {
//	fmt.Println("id = ", id)
//	fmt.Println("xyz: ", line)
	dobj := slmData{id, level, timestamp, line, metadata}
        ob.Call("com.subgraph.EventNotifier.Alert", 0, dobj)
}
