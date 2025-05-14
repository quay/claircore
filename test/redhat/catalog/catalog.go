// Package catalog contains common types for dealing with the Red Hat Container
// Catalog.
//
// See https://catalog.redhat.com/api/containers/docs/index.html for the API
// documentation.
package catalog

import (
	"time"
)

// TODO is a placeholder type used where there is structured data, but nothing
// makes use of it.
type TODO struct{}

// Repository contains metadata associated with Red Hat and ISV repositories.
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/ContainerRepository.html
type Repository struct {
	// MongoDB unique _id
	ID string `json:"_id"`
	// The date when the entry was created. Value is created automatically on creation.
	CreationDate time.Time `json:"creation_date"`
	// The date when the entry was last updated.
	LastUpdateDate time.Time `json:"last_update_date"`
	// The application categories (types).
	ApplicationCategories []string `json:"application_categories"`
	// What build categories does this fall into, such as standalone, s2i builder, etc.
	BuildCategories []string `json:"build_categories"`
	DisplayData     TODO     `json:"display_data"`
	// Defines whether a repository contains multiple image streams.
	MultipleContentStreams bool `json:"includes_multiple_content_streams"`
	// Repository is intended for non-production use only.
	NonProductionOnly bool `json:"non_production_only"`
	// Indicates if images in this repository are allowed to run super-privileged.
	PrivilegedImagesAllowed bool `json:"privileged_images_allowed"`
	ProtectedForPull        bool `json:"protected_for_pull"`
	// Indicates whether the repository requires subscription or other access restrictions for search.
	ProtectedForSearch bool `json:"protected_for_search"`
	// Indicates that the repository does not have any images in it or has been deleted.
	Published bool `json:"published"`
	// Hostname of the registry where the repository can be accessed.
	Registry string `json:"registry"`
	// The release categories of a repository.
	ReleaseCategories []string `json:"release_categories"`
	// Combination of image repository and namespace.
	Repository string `json:"repository"`
	// Label of the vendor that owns this repository.
	VendorLabel string `json:"vendor_label"`
	// Contains unique list of all container architectures for the given repository.
	Architectures []string `json:"architectures"`
	// Denote which tags to be used for auto-rebuilding processes.
	AutoRebuildTags []string `json:"auto_rebuild_tags"`
	// Flag indicating whether the repository has opted-in to auto-release auto-built images.
	CanAutoReleaseCVERebuild bool   `json:"can_auto_release_cve_rebuild"`
	CDNBaseURL               string `json:"cdn_base_url"`
	// Capture and provide an inventory of grades corresponding to the tags in the relevant contents stream.
	ContentStreamGrades []TODO `json:"content_stream_grades"`
	// Capture and provide an inventory of tags corresponding to the content streams.
	ContentStreamTags []string `json:"content_stream_tags"`
	// Description of the repository.
	Description string `json:"description"`
	// Links to marketing and doc collateral including categorization (solution brief, white paper, demo video, etc.) supposed to be displayed on the product page (NOT documentation tab on image overview tab).
	DocumentationLinks []TODO `json:"documentation_links"`
	// Flag indicating whether the repository has opted-in to entitlements to determine needed subscriptions in order to be able to pull repository images.
	EntitlementEnabled bool `json:"entitlement_enabled"`
	// List of engineering IDs associated with the repository. The list represents a needed subscription to pull the repository images.
	EngineeringIDs []string `json:"engineering_ids"`
	// Flag indicating which team has opted-in to use the File Based Catalog.
	FBCOptIn bool      `json:"fbc_opt_in"`
	EOLDate  time.Time `json:"eol_date"`
	// Date until the freshness grades for this repository are unknown.
	FreshnessGradesUnknownUntilDate time.Time `json:"freshness_grades_unknown_until_date"`
	// Designates whether a repository is community-supported.
	IsCommunitySupported bool `json:"is_community_supported"`
	// ID of the project in for ISV repositories.
	ISVPID string `json:"isv_pid"`
	// Determine what registry should be used as source of repository metadata (e.g. Pulp or Quay).
	MetadataSource string `json:"metadata_source"`
	// Set of metrics about the repository.
	Metrics TODO `json:"metrics"`
	// Namespace of the repository.
	Namespace  string `json:"namespace"`
	ObjectType string `json:"object_type"`
	// ID of the project in PRM. Only for ISV repositories.
	PRMProjectID string `json:"prm_project_id"`
	// List of unique identifiers for the product listings.
	ProductListings []string `json:"product_listings"`
	// Map repositories to specific product versions.
	ProductVersions []string `json:"product_versions"`
	// Consumed by the Registry Proxy so that it can route users to the proper backend registry (e.g. Pulp or Quay).
	RegistryTarget string `json:"registry_target"`
	// Defines repository to point to in case this one is deprecated.
	ReplacedByRepositoryName string `json:"replaced_by_repository_name"`
	// Flag indicating whether (false) the repository is published on the legacy registry (registry.access.redhat.com), or (true) can only be published to registry.redhat.io.
	RequiresTerms bool `json:"requires_terms"`
	// Describes what the image can be run on.
	RunsOn TODO `json:"runs_on"`
	// Flag indicating whether images associated with this repo are included in workflows where non-binary container images are published alongside their binary counterparts.
	SourceContainerImageEnabled bool `json:"source_container_image_enabled"`
	// The support levels of a repository.
	SupportLevels []string `json:"support_levels"`
	// Total size of all images in bytes.
	TotalSizeBytes int64 `json:"total_size_bytes"`
	// Total size of all uncompressed images in bytes.
	TotalUncompressedSizeBytes int64 `json:"total_uncompressed_size_bytes"`
	// When populated this field will override the content on the ‘get this image’ tab in red hat container catalog.
	UIGetThisImageOverride string `json:"ui_get_this_image_override"`
	// Flag indicating whether the ‘latest’ tag for an image should be pulled.
	UseLatest bool `json:"use_latest"`
	// Marketplace related information.
	Marketplace TODO `json:"marketplace"`

	Links map[string]Link `json:"_links"`
}

// Link is a hypermedia pointer.
//
// Not explicitly documented.
type Link struct {
	Href string `json:"href"`
}

// Images is the top-level response for listing images belonging to a
// repository.
//
// Not explicitly documented.
type Images struct {
	Data []Image `json:"data"`
}

// Image is metadata about images contained in RedHat and ISV repositories.
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/ContainerImage.html
type Image struct {
	// MongoDB unique _id
	ID string `json:"_id"`
	// The field contains an architecture for which the container image was built for. Value is used to distinguish between the default x86-64 architecture and other architectures. If the value is not set, the image was built for the x86-64 architecture.
	Archtecture string `json:"architecture"`
	// Published repositories associated with the container image.
	Repositories []TODO `json:"repositories"`
	// Indication if the image was certified.
	Certified bool `json:"certified"`
	// Brew related metadata.
	Brew TODO `json:"brew"`
	// Indication that image was created by the CPaaS managed service pipeline.
	CloudService bool `json:"cloud_service"`
	// Information about the state of grading of particular image.
	ContainerGrades TODO `json:"container_grades"`
	// A list of all content sets (YUM repositories) from where an image RPM content is.
	ContentSets []string `json:"content_sets"`
	// A mapping of applicable advisories to RPM NEVRA. This data is required for scoring.
	CPEIDs []string `json:"cpe_ids"`
	// A mapping of applicable advisories for the base_images from the Red Hat repositories.
	CPEIDsRHBaseImages []string `json:"cpe_ids_rh_base_images"`
	// Docker Image Digest. For Docker 1.10+ this is also known as the ‘manifest digest’.
	DockerImageDigest string `json:"docker_image_digest"`
	// Docker Image ID. For Docker 1.10+ this is also known as the ‘config digest’.
	DockerImageID string `json:"docker_image_id"`
	// The grade based on applicable updates and time provided by PST CVE engine.
	FreshnessGrades []TODO `json:"freshness_grades"`
	ObjectType      string `json:"object_type"`
	// Data parsed from image metadata. These fields are not computed from any other source.
	ParsedData ParsedData `json:"parsed_data"`
	// Information if there is an existing exception for the test_results, given by certOps resulting in successful certification.
	TestResultsException TODO `json:"test_results_exception"`
	// Indicates that an image was removed. Only unpublished images can be removed.
	Deleted bool `json:"deleted"`
	// Image manifest digest. Be careful, as this value is not unique among container image entries, as one image can be references several times.
	ImageID string `json:"image_id"`
	// ID of the project in for ISV repositories. The ID can be also used to connect vendor to the image.
	ISVPID string `json:"isv_pid"`
	// The total size of the sum of all layers for each image in bytes. This is computed externally and may not match what is reported by the image metadata (see parsed_data.size).
	SumLayerSizeBytes int64 `json:"sum_layer_size_bytes"`
	// Field for multiarch primary key
	TopLayerID string `json:"top_layer_id"`
	// Hash (sha256) of the uncompressed top layer for this image (should be same value as - parsed_data.uncompressed_layer_sizes.0.layer_id)
	UncompressedTopLayerID string `json:"uncompressed_top_layer_id"`
	// Raw image configuration, such as output from docker inspect.
	RawConfig string `json:"raw_config"`
	// The date when the entry was created. Value is created automatically on creation.
	CreationDate time.Time `json:"creation_date"`
	// The date when the entry was last updated.
	LastUpdateDate time.Time `json:"last_update_date"`
	// Red Hat Org ID / account_id from Red Hat SSO. Also corresponds to company_org_id in Red Hat Connect.
	OrgID int64 `json:"org_id"`

	Links map[string]Link `json:"_links"`
}

// ParsedData has no description.
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/ParsedData.html
type ParsedData struct {
	Architecture string `json:"architecture"`
	Author       string `json:"author"`
	Command      string `json:"command"`
	Comment      string `json:"comment"`
	Container    string `json:"container"`
	// The 'created' date reported by image metadata. Stored as String because we do not have control on that format.
	Created           string `json:"created"`
	DockerImageDigest string `json:"docker_image_digest"`
	DockerImageID     string `json:"docker_image_id"`
	// Version of docker reported by ‘docker inspect’ for this image.
	DockerVersion string   `json:"docker_version"`
	EnvVariables  []string `json:"env_variables"`
	ImageID       string   `json:"image_id"`
	Labels        []TODO   `json:"labels"`
	// Layer digests from the image.
	Layers []string `json:"layers"`
	OS     string   `json:"os"`
	Ports  string   `json:"ports"`
	// Repositories defined within an image as reported by yum command.
	Repos []ParsedDataRepo `json:"repos"`
	// Size of this image as reported by image metadata.
	Size int64 `json:"size"`
	// Information about uncompressed layer sizes.
	UncompressedLayerSizes []TODO `json:"uncompressed_layer_sizes"`
	// Uncompressed images size in bytes (sum of uncompressed layers size).
	UncompressedSizeBytes int64 `json:"uncompressed_size_bytes"`
	// The user on the images.
	User string `json:"user"`
	// Virtual size of this image as reported by image metadata.
	VirtualSize int64 `json:"virtual_size"`
}

// BUG(hank) The [ParsedData.Layers] slice is backwards: the last-applied layer
// is at the 0th position. OCI types have the first-applied layer in the 0th
// position.

// TopLayer is a helper to work around the layer notation difference.
//
// See the BUG note for more information.
func (d *ParsedData) TopLayer() string {
	return d.Layers[0]
}

// ParsedDataRepo has no description.
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/ParsedDataRepo.html
type ParsedDataRepo struct {
	BaseURL  string `json:"baseurl"`
	Expire   string `json:"expire"`
	Filename string `json:"filename"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Packages string `json:"pkgs"`
	Size     string `json:"size"`
	Updated  string `json:"updated"`
}

// RpmManifest contains all the RPM packages for a given [Image].
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/ContainerImageRPMManifest.html
type RpmManifest struct {
	// MongoDB unique _id
	ID string `json:"_id"`
	// The foreign key to [Image.ID].
	ImageID    string `json:"image_id"`
	ObjectType string `json:"object_type"`
	// Content manifest of this image. RPM content included in the image.
	RPMs []RpmsItems `json:"rpms"`
	// The date when the entry was created. Value is created automatically on creation.
	CreationDate time.Time `json:"creation_date"`
	// The date when the entry was last updated.
	LastUpdateDate time.Time `json:"last_update_date"`
}

// RpmsItems is the RPM content of an image.
//
// This is poorly named, as it describes a single rpm package.
//
// Implements the object described at https://catalog.redhat.com/api/containers/docs/objects/RpmsItems.html
type RpmsItems struct {
	// RPM architecture.
	Architecture string `json:"architecture"`
	// GPG key used to sign the RPM.
	GPG string `json:"gpg"`
	// RPM name.
	Name string `json:"name"`
	// RPM name, version, release, and architecture.
	NVRA string `json:"nvra"`
	// RPM release.
	Release string `json:"release"`
	// Source RPM name.
	SrpmName string `json:"srpm_name"`
	// Source RPM NEVRA (name, epoch, version, release, architecture).
	SrpmNEVRA string `json:"srpm_nevra"`
	// RPM summary.
	Summary string `json:"summary"`
	// RPM version.
	Version string `json:"version"`

	// Extensions used only in claircore code:

	Epoch          string `json:"_epoch,omitempty"`
	Module         string `json:"_module,omitempty"`
	RepositoryHint string `json:"_repositoryhint,omitempty"`
}
