package ohauth

func firstValueStr(strs ...string) (val string) {
	for _, v := range strs {
		if v != "" {
			val = v
			break
		}
	}
	return
}
