package aws.cryptography.mpl.testserver.orchestrator.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ConfigurationEntry(
    @JsonProperty("language") String language,
    @JsonProperty("majorVersion") int majorVersion,
    @JsonProperty("port") int port,
    @JsonProperty("commonsConfigurationPath") String commonsConfigurationPath,
    @JsonProperty("serverLocation") ServerLocation serverLocation
) {
    public String serverPath() {
        return serverLocation != null ? serverLocation.path() : "";
    }
}
