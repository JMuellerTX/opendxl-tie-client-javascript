'use strict'
/* eslint no-unused-expressions: "off" */

const expect = require('chai').expect
const dxl = require('@opendxl/dxl-client')
const MessageUtils = require('@opendxl/dxl-bootstrap').MessageUtils
const TieClient = require('..').TieClient

function createMockDxlClient () {
  const registered = {}
  return {
    registered,
    addEventCallback: function (topic, cb) {
      registered[topic] = registered[topic] || []
      registered[topic].push(cb)
    },
    removeEventCallback: function (topic, cb) {
      const list = registered[topic]
      if (list) {
        const idx = list.indexOf(cb)
        if (idx >= 0) {
          list.splice(idx, 1)
        }
      }
    }
  }
}

describe('TieClient event callbacks', function () {
  it('scopes callback wrappers per topic and client instance without mutating callback', function () {
    const dxlClient1 = createMockDxlClient()
    const dxlClient2 = createMockDxlClient()
    const tieClient1 = new TieClient(dxlClient1)
    const tieClient2 = new TieClient(dxlClient2)

    const received = []
    const sharedCallback = function (payload, event) {
      received.push({ payload, topic: event.destinationTopic })
    }

    tieClient1.addFileDetectionCallback(sharedCallback)
    tieClient1.addFileFirstInstanceCallback(sharedCallback)
    tieClient2.addFileDetectionCallback(sharedCallback)

    expect(sharedCallback._dxlWrapper).to.be.undefined

    const detectionTopic = '/mcafee/event/tie/file/detection'
    const firstInstanceTopic = '/mcafee/event/tie/file/firstinstance'

    expect(dxlClient1.registered[detectionTopic]).to.have.lengthOf(1)
    expect(dxlClient1.registered[firstInstanceTopic]).to.have.lengthOf(1)
    expect(dxlClient2.registered[detectionTopic]).to.have.lengthOf(1)
    expect(dxlClient1.registered[detectionTopic][0]).to.not.equal(
      dxlClient1.registered[firstInstanceTopic][0]
    )

    const event = new dxl.Event(firstInstanceTopic)
    MessageUtils.objectToJsonPayload(event, {
      hashes: [{ type: 'md5', value: Buffer.from('eb5e2b9dc51817a086d7b97eb52410ab', 'hex').toString('base64') }]
    })
    dxlClient1.registered[firstInstanceTopic][0](event)
    expect(received).to.have.lengthOf(1)
    expect(received[0].payload.hashes.md5).to.equal('eb5e2b9dc51817a086d7b97eb52410ab')

    tieClient1.removeFileDetectionCallback(sharedCallback)
    expect(dxlClient1.registered[detectionTopic]).to.be.empty
    expect(dxlClient1.registered[firstInstanceTopic]).to.have.lengthOf(1)
    expect(dxlClient2.registered[detectionTopic]).to.have.lengthOf(1)

    tieClient1.removeFileFirstInstanceCallback(sharedCallback)
    expect(dxlClient1.registered[firstInstanceTopic]).to.be.empty

    tieClient2.removeFileDetectionCallback(sharedCallback)
    expect(dxlClient2.registered[detectionTopic]).to.be.empty
  })
})
