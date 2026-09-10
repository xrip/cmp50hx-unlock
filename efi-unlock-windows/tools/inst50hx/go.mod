module 50hxinstaller

go 1.26.5

require (
	50hxcore v0.0.0
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	golang.org/x/sys v0.47.0
)

require (
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
)

replace 50hxcore => ../50hxcore
