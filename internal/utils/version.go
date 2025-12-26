package utils

var sceptuneVersion = "dev"

func GetSceptuneName() string {
	return "sceptune/v" + sceptuneVersion
}

func GetSceptuneVersion() string {
	return sceptuneVersion
}