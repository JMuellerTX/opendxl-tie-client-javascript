'use strict'

const common = require('../common')
const dxl = common.require('@opendxl/dxl-client')
const MessageUtils = common.require('@opendxl/dxl-bootstrap').MessageUtils
const TieClient = common.require('@opendxl/dxl-tie-client').TieClient

// Create DXL configuration from file
const config = dxl.Config.createDxlConfigFromFile(common.CONFIG_FILE)

// Create the client
const client = new dxl.Client(config)

// Connect to the fabric, supplying a callback function which is invoked
// when the connection has been established
client.connect(function () {
  // Create the McAfee Threat Intelligence Exchange (TIE) client
  const tieClient = new TieClient(client)

  // Register detection callback with the client
  tieClient.addFileDetectionCallback(function (detectionObj, originalEvent) {
    // Display the DXL topic that the event was received on
    console.log('Detection on topic: ' + originalEvent.destinationTopic)
    // Dump the detection info
    console.log(MessageUtils.objectToJson(detectionObj, true))
  })

  // Wait forever
  console.log('Waiting for detection events...')
})
