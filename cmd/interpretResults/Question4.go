package main

type Question4SimpleResult struct {
	Domain               string
	CensoringV4Resolvers map[string]struct{}
	CensoringV6Resolvers map[string]struct{}
}

func Question4(args InterpretResultsFlags) {
	infoLogger.Println(
		"Answering Question 4: How were domains censored by resolver address " +
			"family and by record requests",
	)

}
