package aws.cryptography.primitives.testserver.orchestrator.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ConfigurationSet(
    @JsonProperty("product") String product,
    @JsonProperty("features") List<String> features,
    @JsonProperty("entries") List<ConfigurationEntry> entries
) {
}
