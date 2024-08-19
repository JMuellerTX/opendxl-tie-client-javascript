'use strict'

const common = require('../common')
const dxl = common.require('@opendxl/dxl-client')
const MessageUtils = common.require('@opendxl/dxl-bootstrap').MessageUtils
const tie = common.require('@opendxl/dxl-tie-client')
const CertProvider = tie.CertProvider
const CertEnterpriseAttrib = tie.CertEnterpriseAttrib
const CertReputationProp = tie.CertReputationProp
const EpochUtil = tie.EpochUtil
const FileProvider = tie.FileProvider
const FileEnterpriseAttrib = tie.FileEnterpriseAttrib
const FileReputationProp = tie.FileReputationProp
const HashType = tie.HashType
const TieClient = tie.TieClient

// Create DXL configuration from file
const config = dxl.Config.createDxlConfigFromFile(common.CONFIG_FILE)

// Create the client
const client = new dxl.Client(config)

// Hashes for the file to look up (notepad.exe)
// These can be replaced by a file which is known to have run within the
// enterprise for better results
const FILE_MD5 = 'f2c7bb8acc97f92e987a2d4087d021b1'
const FILE_SHA1 = '7eb0139d2175739b3ccb0d1110067820be6abd29'
const FILE_SHA256 = '142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2'

// Hashes for the certificate to look up
// These can be replaced by a certificate which is known to have run within the
// enterprise for better results
const CERTIFICATE_BODY_SHA1 = '6eae26db8c13182a7947982991b4321732cc3de2'
const CERTIFICATE_PUBLIC_KEY_SHA1 = '3b87a2d6f39770160364b79a152fcc73bae27adf'

// Connect to the fabric, supplying a callback function which is invoked
// when the connection has been established
client.connect(function () {
  // Create the McAfee Threat Intelligence Exchange (TIE) client
  const tieClient = new TieClient(client)

  const fileHashes = {}
  fileHashes[HashType.MD5] = FILE_MD5
  fileHashes[HashType.SHA1] = FILE_SHA1
  fileHashes[HashType.SHA256] = FILE_SHA256

  // Perform the file reputation query
  tieClient.getFileReputation(
    function (fileReputationError, fileReputations) {
      if (fileReputationError) {
        // Destroy the client - frees up resources so that the application
        // stops running
        client.destroy()
        console.log('Error getting file reputations: ' +
          fileReputationError.message)
      } else {
        console.log('File reputation response:')

        // Display the Global Threat Intelligence (GTI) trust level for the file
        const fileGtiRep = fileReputations[FileProvider.GTI]
        if (fileGtiRep) {
          console.log('\tGlobal Threat Intelligence (GTI) trust level: ' +
            fileGtiRep[FileReputationProp.TRUST_LEVEL])
        }

        // Display the Enterprise reputation information
        const fileEntRep = fileReputations[FileProvider.ENTERPRISE]
        if (fileEntRep) {
          // Retrieve the enterprise reputation attributes
          const entRepAttribs = fileEntRep[FileReputationProp.ATTRIBUTES]

          // Display prevalence (if it exists)
          const prevalenceAttrib = entRepAttribs[FileEnterpriseAttrib.PREVALENCE]
          if (prevalenceAttrib) {
            console.log('\tEnterprise prevalence: ' + prevalenceAttrib)
          }

          // Display first contact date (if it exists)
          const firstContactAttrib =
            entRepAttribs[FileEnterpriseAttrib.FIRST_CONTACT]
          if (firstContactAttrib) {
            console.log('\tFirst contact: ' +
              EpochUtil.toLocalTimeString(firstContactAttrib))
          }
        }

        // Display the full file reputation response
        console.log('\nFull file reputation response:\n' +
          MessageUtils.objectToJson(fileReputations, true) + '\n')

        // Perform the certificate reputation query
        tieClient.getCertificateReputation(
          function (certReputationError, certReputations) {
            // Destroy the client - frees up resources so that the application
            // stops running
            client.destroy()
            if (certReputationError) {
              console.log('Error getting certificate reputations: ' +
                certReputationError.message)
            } else {
              console.log('Certificate reputation response:')

              // Display the Global Threat Intelligence(GTI) trust level for the
              // certificate
              const certGtiRep = certReputations[CertProvider.GTI]
              if (certGtiRep) {
                console.log('\tGlobal Threat Intelligence (GTI) trust level: ' +
                  certGtiRep[CertReputationProp.TRUST_LEVEL])
              }

              // Display the Enterprise reputation information
              const certEntRep = certReputations[CertProvider.ENTERPRISE]
              if (certEntRep) {
                // Retrieve the enterprise reputation attributes
                const entRepAttribs = certEntRep[CertReputationProp.ATTRIBUTES]

                // Display prevalence (if it exists)
                const prevalenceAttrib =
                  entRepAttribs[CertEnterpriseAttrib.PREVALENCE]
                if (prevalenceAttrib) {
                  console.log('\tEnterprise prevalence: ' + prevalenceAttrib)
                }

                // Display first contact date (if it exists)
                const firstContactAttrib =
                  entRepAttribs[CertEnterpriseAttrib.FIRST_CONTACT]
                if (firstContactAttrib) {
                  console.log('\tFirst contact: ' +
                    EpochUtil.toLocalTimeString(firstContactAttrib))
                }
              }

              // Display the full certificate response
              console.log('\nFull certificate reputation response:\n' +
                MessageUtils.objectToJson(certReputations, true))
            }
          },
          CERTIFICATE_BODY_SHA1,
          CERTIFICATE_PUBLIC_KEY_SHA1
        )
      }
    },
    fileHashes
  )
})
