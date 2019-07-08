package cfg

import (
	"errors"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
)

func NewConfig() Config {
	return Config{}
}

func (c *Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
}

func (c *Config) Unmarshal(data []byte) error {
	return yaml.Unmarshal(data, c)
}

func (c *Config) Save() error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("config/config.yaml", data, 0640)
	return err
}

func (c *Config) GenerateSample() error {
	if _, err := os.Stat("config"); os.IsNotExist(err) {
		err = os.Mkdir("config", 0750)
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat("config/config.sample.yaml"); os.IsNotExist(err) {
		c.Providers = []Provider{
			{
				Config: oauth2.Config{
					ClientID:     "my_client_id",
					ClientSecret: "my_client_secret",
					Scopes:       []string{"scope1", "scope2"},
					Endpoint:     oauth2.Endpoint{},
				},
				Enabled: false,
				Name:    "Twitter",
			},
		}
		data, err := c.Marshal()
		if err != nil {
			return err
		}
		f, err := os.Create("config/config.sample.yaml")
		if err != nil {
			return err
		}
		defer f.Close()

		n, err := f.Write(data)
		log.Printf("Wrote %d bytes", n)
		err = f.Sync()
		if err != nil {
			return err
		}
	} else {
		return errors.New("config already exists")
	}
	return nil
}
