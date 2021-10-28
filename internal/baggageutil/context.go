package baggageutil

import (
	"context"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
)

// ContextWithValues adds a list of key value pairs to the context's baggage. kvPairs must be of even length.
func ContextWithValues(ctx context.Context, kvPairs ...string) context.Context {
	if len(kvPairs) == 0 {
		return ctx
	}

	b := baggage.FromContext(ctx)
	oldMembers := b.Members()
	newMembers := make([]baggage.Member, 0, len(oldMembers)+len(kvPairs)/2)
	newMembers = append(newMembers, oldMembers...)
	for i := 0; i < len(kvPairs); i += 2 {
		member, err := baggage.NewMember(kvPairs[i], kvPairs[i+1])
		if err != nil {
			zlog.Warn(ctx).Err(err).Str("key", kvPairs[i]).Msg("could not create baggage member for context")
			continue
		}
		newMembers = append(newMembers, member)
	}
	if len(kvPairs)%2 != 0 {
		zlog.Warn(ctx).Str("key", kvPairs[len(kvPairs)-1]).Msg("key with no value in baggage")
	}
	newBaggage, err := baggage.New(newMembers...)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not create new baggage for context")
		return ctx
	}
	return baggage.ContextWithBaggage(ctx, newBaggage)
}
