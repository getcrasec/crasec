package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/csafpublish"
)

var (
	csafPublishWellKnown           string
	csafPublishBaseURL             string
	csafPublishAdvisory            string
	csafPublishRole                string
	csafPublishListOnAggregators   bool
	csafPublishMirrorOnAggregators bool
)

var csafPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish a CSAF advisory to a .well-known/csaf/ discovery directory",
	Long: `Publish an advisory into the CSAF "well-known" directory layout so
downstream tools, aggregators, and market-surveillance authorities can find
it without knowing a specific URL — the discovery mechanism ENISA expects
CRA vulnerability disclosures to use
(https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7-distributing-csaf-documents).

Given --well-known ./public, this:

  1. Validates --advisory against the CSAF 2.0 schema, then copies it to
     ./public/.well-known/csaf/advisories/<tracking-id>.json (filename
     derived from document.tracking.id per the CSAF filename convention),
     alongside SHA-256/SHA-512 checksums and its Sigstore .sig bundle if one
     exists next to the source file.
  2. Regenerates ./public/.well-known/csaf/index.txt to list every advisory
     currently in the advisories/ directory, not just the one just published.
  3. Creates or refreshes ./public/.well-known/csaf/provider-metadata.json:
     publisher/canonical_url/role/timestamps come from --base-url and the
     advisory's own document.publisher; anything else already in the file
     (e.g. a manually added public_openpgp_keys entry) is preserved.

--base-url is the origin the directory will actually be served from, e.g.
https://crasec.io — required, since canonical_url and the distribution's
directory_url must be absolute.

  crasec csaf generate ... -o advisory.json
  crasec csaf sign advisory.json
  crasec csaf publish --well-known ./public --base-url https://crasec.io

Deploy ./public/.well-known/csaf/ at the site root (so it resolves at
https://crasec.io/.well-known/csaf/provider-metadata.json) to complete
publication.`,
	RunE: runCSAFPublish,
}

func init() {
	csafCmd.AddCommand(csafPublishCmd)

	csafPublishCmd.Flags().StringVar(&csafPublishWellKnown, "well-known", "", "root directory to publish into; .well-known/csaf/ is created underneath it (required)")
	csafPublishCmd.Flags().StringVar(&csafPublishBaseURL, "base-url", "", "public origin the directory will be served from, e.g. https://crasec.io (required)")
	csafPublishCmd.Flags().StringVar(&csafPublishAdvisory, "advisory", "advisory.json", "path to the advisory to publish")
	csafPublishCmd.Flags().StringVar(&csafPublishRole, "role", "csaf_provider", "CSAF provider role: csaf_publisher, csaf_provider, or csaf_trusted_provider")
	csafPublishCmd.Flags().BoolVar(&csafPublishListOnAggregators, "list-on-aggregators", true, "set provider-metadata.json's list_on_CSAF_aggregators")
	csafPublishCmd.Flags().BoolVar(&csafPublishMirrorOnAggregators, "mirror-on-aggregators", false, "set provider-metadata.json's mirror_on_CSAF_aggregators")

	for _, f := range []string{"well-known", "base-url"} {
		if err := csafPublishCmd.MarkFlagRequired(f); err != nil {
			panic(err)
		}
	}
}

func runCSAFPublish(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	res, err := csafpublish.Publish(csafPublishAdvisory, csafpublish.Options{
		WellKnownRoot:       csafPublishWellKnown,
		BaseURL:             csafPublishBaseURL,
		Role:                csafPublishRole,
		ListOnAggregators:   csafPublishListOnAggregators,
		MirrorOnAggregators: csafPublishMirrorOnAggregators,
	})
	if err != nil {
		return err
	}

	out := cmd.ErrOrStderr()
	fmt.Fprintf(out, "published %s -> %s\n", res.TrackingID, res.AdvisoryPath)
	fmt.Fprintf(out, "wrote %s (%d advisories)\n", res.IndexPath, res.AdvisoryCount)
	fmt.Fprintf(out, "wrote %s\n", res.ProviderMetadataPath)
	return nil
}
