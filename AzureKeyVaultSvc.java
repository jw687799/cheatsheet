import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import com.att.eda.mq.bridge.data.KeyVault;
import com.att.eda.mq.bridge.data.KeyVaultCacheEntry;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.SecretProperties;

@Service
public class KeyVaultService {
    
    private final String keyVaultUrl;
    private final String tenantId;
    private final String clientId;
    private final String clientKey;
    private static final String REGEX_SECRET_PREFIX = "^(mq-).*?";
    private static final String REGEX_PASS_PREFIX = "^(mq-pass-).*?";
    private Pattern pattern = Pattern.compile(REGEX_SECRET_PREFIX, Pattern.CASE_INSENSITIVE);
    private Pattern patternPass = Pattern.compile(REGEX_PASS_MQ_BRIDGE, Pattern.CASE_INSENSITIVE);
    
    public KeyVaultService(@Value("${azure_keyvault_uri}") String keyVaultUrl,
            @Value("${azure_keyvault_tenant_id}") String tenantId,
            @Value("${azure_keyvault_client_id}") String clientId,
            @Value("${azure_keyvault_client_key}") String clientKey) {
        this.keyVaultUrl = keyVaultUrl;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientKey = clientKey;
        
    }
    
    /**
     * Used to create a secret client to interact with keyvault
     * 
     * @return secret client used to execute commands
     */
    @Bean("AzureCreds")
    public SecretClient getSecretClient() {
        ClientSecretCredential credential = new ClientSecretCredentialBuilder().tenantId(tenantId)
                .clientId(clientId).clientSecret(clientKey).build();
        
        // Azure SDK client builders accept the credential as a parameter
        return new SecretClientBuilder().vaultUrl(keyVaultUrl).credential(credential).buildClient();
    }
    
    /**
     * reads all passwords from keyvault that start with mq-bridge-conn-pass-
     * 
     * @return Map of secret and their value
     */
    public Map<String, KeyVaultCacheEntry> readPassSecret() {
        var secretClient = getSecretClient();
        Map<String, KeyVaultCacheEntry> response = new HashMap<>();
        var propertyList = secretClient.listPropertiesOfSecrets();
        if (propertyList != null) {
            for (SecretProperties secret : propertyList) {
                if (patternPass.matcher(secret.getName()).find()
                        && Boolean.TRUE.equals(secret.isEnabled())) {
                    Optional<KeyVaultCacheEntry> cacheEntryOptional =
                            fetchKeyVaultCacheEntry(secret.getName());
                    if (cacheEntryOptional.isPresent()) {
                        response.put(secret.getName(), cacheEntryOptional.get());
                    }
                }
            }
            return response;
        } else {
            throw new IllegalArgumentException();
        }
    }
    
    /**
     * Read secret from key vault and return entry for cache
     * 
     * @param  secretName name of secret to retrieve
     * @return            cache entry
     */
    public Optional<KeyVaultCacheEntry> fetchKeyVaultCacheEntry(String secretName) {
        KeyVault keyVault = readSecret(secretName);
        return keyVault.getKeyVaultSecret() != null
                ? Optional.of(new KeyVaultCacheEntry(keyVault.getKeyValue(),
                        keyVault.getKeyVaultSecret().getProperties().getUpdatedOn()))
                : Optional.empty();
    }
    
    /**
     * reads secret from keyvault if jks secret it is decoded
     * 
     * @param  secretName name of secret to retrieve
     * @return            KeyVault object
     */
    public KeyVault readSecret(String secretName) {
        var kv = new KeyVault();
        if (pattern.matcher(secretName).find()) {
            var secretClient = getSecretClient();
            kv.setKeyVaultSecret(secretClient.getSecret(secretName));
            if (kv.getKeyVaultSecret() != null) {
                kv.setKeyValue(kv.getKeyVaultSecret().getValue());
                kv.setKeyName(secretName);
                return kv;
            }
            return kv;
        }
        throw new IllegalArgumentException();
    }
    
    /**
     * decodes jks value returned from azure
     * 
     * @param jksValue the value of the jks secret in azure
     */
    public String decodeJksString(String jksValue) {
        byte[] decoder = Base64.getDecoder().decode(jksValue);
        return new String(decoder);
    }
