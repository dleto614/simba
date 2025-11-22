module smbserver

go 1.24.5

require github.com/dleto614/simba v0.0.7

require golang.org/x/crypto v0.45.0 // indirect

// This line tells Go: "When you need github.com/dleto614/simba,
// use the version in the parent directory (..) instead of looking online."
replace github.com/dleto614/simba => ../
