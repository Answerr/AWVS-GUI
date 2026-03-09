package main

import (
	"awvs-client/config"
	"awvs-client/ui"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {
	cfg := config.Load()

	a := app.NewWithID("com.security.awvs-client")
	w := a.NewWindow("AWVS GUI  V1.0  作者：信益安")
	w.Resize(fyne.NewSize(1100, 750))

	w.SetIcon(ui.AppIcon())
	mainUI := ui.NewMainUI(a, w, cfg)
	w.SetContent(mainUI.Build())
	w.CenterOnScreen()
	w.ShowAndRun()
}
