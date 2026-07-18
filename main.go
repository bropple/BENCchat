package main

import (
	"embed"

	"github.com/benco-holdings/benchat/internal/tray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// Application/tray icons, rendered from the R. Triy mark (benco-roster-triy.svg).
// appIconPNG doubles as the Linux window icon; the tray uses PNG on Linux/macOS
// and ICO on Windows.
//
//go:embed assets/appicon.png
var appIconPNG []byte

//go:embed assets/tray.png
var trayIconPNG []byte

//go:embed assets/tray.ico
var trayIconICO []byte

//go:embed assets/tray-badge.png
var trayBadgePNG []byte

//go:embed assets/tray-badge.ico
var trayBadgeICO []byte

func main() {
	app := NewApp()
	app.trayIcons = tray.Icons{
		NormalPNG: trayIconPNG,
		NormalICO: trayIconICO,
		BadgePNG:  trayBadgePNG,
		BadgeICO:  trayBadgeICO,
	}
	app.desktopIcon = appIconPNG

	// The window chrome follows the BENCO palette: a green-tinted near-black
	// base rather than pure black, per the design style guide.
	err := wails.Run(&options.App{
		Title:  "BENCchat",
		Width:  920,
		Height: 640,
		// Opt-in custom titlebar: when on, the window is frameless and the
		// frontend draws BENCchat's own titlebar (see the "Custom window frame"
		// setting). Off by default so the desktop environment decorates normally.
		Frameless:        app.cfg.CustomFrame,
		MinWidth:         720,
		MinHeight:        480,
		BackgroundColour: &options.RGBA{R: 0x0c, G: 0x14, B: 0x08, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnShutdown:    app.shutdown,
		OnBeforeClose: app.beforeClose,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		// The Linux window/taskbar icon (Windows takes its icon from the compiled
		// build/windows/icon.ico that `wails build` embeds from build/appicon.png).
		// ProgramName sets the GTK app-id / WM_CLASS to "benchat", which is what
		// KDE (X11 and Wayland) matches against the installed desktop entry (see
		// installDesktopEntry) to resolve the titlebar/taskbar icon.
		Linux: &linux.Options{
			Icon:        appIconPNG,
			ProgramName: "benchat",
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
