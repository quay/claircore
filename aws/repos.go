package aws

type Repo string

const (
	amzn1 Repo = "amzn1"
	amzn2 Repo = "amzn2"
	amzn2023 Repo = "amzn2023"
)

var ReleaseToRepo = map[Release]Repo{
	AmazonLinux1: amzn1,
	AmazonLinux2: amzn2,
	AmazonLinux2023: amzn2023,
}
