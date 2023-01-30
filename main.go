package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&bunnyDNSProviderSolver{},
	)
}

type bunnyDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type customDNSProviderConfig struct {
	// name of the secret which contains bunnyDNS credentials
	SecretRef string `json:"secretRef"`
	// optional namespace for the secret
	SecretNamespace string `json:"secretNamespace"`
}
type bunnyDNSApiConfig struct {
	apiKey string
	zoneId int
}

func (c *bunnyDNSProviderSolver) getConfig(ch *v1alpha1.ChallengeRequest) (*bunnyDNSApiConfig, error) {
	var secretNs string
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	bunnyCfg := &bunnyDNSApiConfig{}

	if cfg.SecretNamespace != "" {
		secretNs = cfg.SecretNamespace
	} else {
		secretNs = ch.ResourceNamespace
	}

	sec, err := c.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.SecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	bunnyCfg.apiKey, err = stringFromSecretData(&sec.Data, "api-key")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'api-key' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	zoneIdStr, err := stringFromSecretData(&sec.Data, "zone-id")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'zone-id' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}
	bunnyCfg.zoneId, err = strconv.Atoi(zoneIdStr)
	if err != nil {
		return nil, fmt.Errorf("unable to get 'zone-id' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	return bunnyCfg, nil
}

func (c *bunnyDNSProviderSolver) Name() string {
	return "bunny"
}

type NewDnsRecordRequest struct {
	Id    int
	Type  int
	Value string
	Name  string
}

var dnsRecordId = rand.Intn(99999999999)

func (c *bunnyDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := c.getConfig(ch)
	if err != nil {
		return err
	}

	url := "https://api.bunny.net/dnszone/" + strconv.Itoa(cfg.zoneId) + "/records"

	data, _ := json.Marshal(
		NewDnsRecordRequest{
			Id:    dnsRecordId,
			Type:  3,
			Value: ch.Key,
			Name:  ch.DNSName,
		},
	)

	payload := strings.NewReader(string(data))

	req, _ := http.NewRequest("PUT", url, payload)
	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")
	req.Header.Add("AccessKey", cfg.apiKey)

	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()

	if res.StatusCode != 200 {
		fmt.Errorf("can't create new DNS record for zone id %q", cfg.zoneId)
		return nil
	}

	return nil
}

func (c *bunnyDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := c.getConfig(ch)
	if err != nil {
		return err
	}

	url := "https://api.bunny.net/dnszone/" + strconv.Itoa(cfg.zoneId) + "/records/" + strconv.Itoa(dnsRecordId)

	req, _ := http.NewRequest("DELETE", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("AccessKey", cfg.apiKey)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	return nil
}

func (c *bunnyDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl
	return nil
}

func stringFromSecretData(secretData *map[string][]byte, key string) (string, error) {
	data, ok := (*secretData)[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
