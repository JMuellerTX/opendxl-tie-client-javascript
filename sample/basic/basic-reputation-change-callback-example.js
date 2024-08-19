'use strict'

const common = require('../common')
const dxl = common.require('@opendxl/dxl-client')
const MessageUtils = common.require('@opendxl/dxl-bootstrap').MessageUtils
const TieClient = common.require('@opendxl/dxl-tie-client').TieClient

// Create DXL configuration from file
const config = dxl.Config.createDxlConfigFromFile(common.CONFIG_FILE)

// Create the client
const client = new dxl.Client(config)

// Define the callback to receive reputation change events
const repChangeCallback = function (repChangeObj, originalEvent) {
  // Display the DXL topic that the event was received on
  console.log('Reputation change on topic: ' +
    originalEvent.destinationTopic)
  // Dump the reputation change info
  console.log(MessageUtils.objectToJson(repChangeObj, true))
}

// Connect to the fabric, supplying a callback function which is invoked
// when the connection has been established
client.connect(function () {
  // Create the McAfee Threat Intelligence Exchange (TIE) client
  const tieClient = new TieClient(client)

  // Register callbacks with client to receive both file and certificate
  // reputation change events
  tieClient.addFileReputationChangeCallback(repChangeCallback)
  tieClient.addCertificateReputationChangeCallback(repChangeCallback)

  // Wait forever
  console.log('Waiting for reputation change events...')
})
