package settings_test

import (
	"github.com/efrenfuentes/go-utils/settings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
)

var _ = Describe("Settings", func() {
	Describe("Load environment", func() {
		It("Load correct environment", func() {
			environments := []string{"development", "production", "test"}
			for _, environment := range environments {
				os.Setenv("GO_ENV", environment)
				settings.Init()

				if environment == "test" {
					Expect(settings.IsTestEnvironment()).To(BeTrue())
				} else {
					Expect(settings.IsTestEnvironment()).To(BeFalse())
				}

				Expect(settings.GetEnvironment()).To(Equal(environment))
			}
		})
	})
	Describe("Reading settings", func() {
		BeforeEach(func() {
			os.Setenv("GO_ENV", "development")
			settings.Init()
		})
		It("Read values", func() {
			mySettings := settings.Get()

			Expect(mySettings["Application"]).To(Equal("Name of Application"))
			Expect(mySettings["Version"]).To(Equal(float64(1)))
			Expect(mySettings["Array"]).To(Equal([]interface{}{"Element 1", "Element 2"}))
			Expect(mySettings["Parent"].(map[string]interface{})["Child1"]).To(Equal(float64(1)))
			Expect(mySettings["Parent"].(map[string]interface{})["Child2"]).To(Equal(float64(2)))
		})
	})
})

