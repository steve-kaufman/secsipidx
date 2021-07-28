package secsipid

type SJWTLibOptions struct {
	CacheDirPath string
	CacheExpire  int
	CertCAFile   string
	CertCAInter  string
	CertCRLFile  string
	CertVerify   int
	X5u          string
}

func (options SJWTLibOptions) ShouldVerifyWithTime() bool {
	return (options.CertVerify & (1 << 0)) != 0
}

func (options SJWTLibOptions) ShouldVerifyWithSystemCA() bool {
	return (options.CertVerify & (1 << 1)) != 0
}

func (options SJWTLibOptions) ShouldVerifyWithCustomCA() bool {
	return (options.CertVerify & (1 << 2)) != 0
}

func (options SJWTLibOptions) ShouldVerifyWithIntermediateCA() bool {
	return (options.CertVerify & (1 << 3)) != 0
}

func (options SJWTLibOptions) ShouldVerifyWithCLRFile() bool {
	return (options.CertVerify & (1 << 4)) != 0
}
