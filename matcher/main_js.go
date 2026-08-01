//go:build js && wasm

package main

import "syscall/js"

func main() {
	js.Global().Set("squawkCompare", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 {
			return `{"kind":"error","reason":"expected one argument"}`
		}
		return compareJSON(args[0].String())
	}))
	select {}
}
