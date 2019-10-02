package aws

type Repo string

const (
	amzn1 Repo = "amzn1"
	amzn2 Repo = "amzn2"
)

var ReleaseToRepo = map[Release]Repo{
	Linux1: amzn1,
	Linux2: amzn2,
}
