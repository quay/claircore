package aws

type Repo string

const (
	amzn1 Repo = "amzn1"
	amzn2 Repo = "amzn2"
	amzn2023 Repo = "amzn2023"
)

var ReleaseToRepo = map[Release]Repo{
	Linux1: amzn1,
	Linux2: amzn2,
	Linux2023: amzn2023,
}
