package aws.cryptography.primitives.testserver.orchestrator.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ServerLocation(
    @JsonProperty("repository") String repository,
    @JsonProperty("url") String url,
    @JsonProperty("ref") String ref,
    @JsonProperty("path") String path
) {
}
