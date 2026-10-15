// Package web contains immutable, locally served terminal lab assets.
package web

import "embed"

//go:embed index.html app.mjs paste.mjs remote.mjs style.css desktop.html desktop.mjs desktop.css auth-login.html auth-workspace.html auth.mjs auth.css custody-login.html custody-workspace.html custody.mjs custody.css vendor/*
var Assets embed.FS
