package main

import (
	"fmt"
        "github.com/godbus/dbus"
)

type dbusObject struct {
        dbus.BusObject
}

func newDbusObject() (*dbusObject, error) {
        conn, err := dbus.SystemBus()
        if err != nil {
                return nil, err
        }
        return &dbusObject{conn.Object("com.subgraph.EventNotifier", "/com/subgraph/EventNotifier")}, nil

}
func (ob *dbusObject) alert(message string) {
	fmt.Println(message)
        ob.Call("com.subgraph.EventNotifier.Alert", 0, message)
}


