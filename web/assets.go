// Package web contains immutable, locally served terminal lab assets.
package web

import "embed"

//go:embed index.html app.mjs paste.mjs style.css vendor/*
var Assets embed.FS
