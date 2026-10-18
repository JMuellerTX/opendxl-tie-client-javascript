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

  it('drops events with mismatched agentGuid when verifySource is enabled', function () {
    const dxlClient = createMockDxlClient()
    const tieClient = new TieClient(dxlClient)
    const received = []

    tieClient.addFileDetectionCallback(function (payload) {
      received.push(payload)
    }, true)

    const detectionTopic = '/mcafee/event/tie/file/detection'
    const spoofedEvent = new dxl.Event(detectionTopic)
    spoofedEvent.sourceClientId = '{11111111-2222-3333-4444-555555555555}'
    MessageUtils.objectToJsonPayload(spoofedEvent, {
      agentGuid: '{abc5d2c6-e959-11e3-baeb-005056c00009}',
      name: 'SPOOFED.EXE'
    })
    dxlClient.registered[detectionTopic][0](spoofedEvent)
    expect(received).to.be.empty

    const legitEvent = new dxl.Event(detectionTopic)
    legitEvent.sourceClientId = 'ABC5D2C6-E959-11E3-BAEB-005056C00009:inst-1'
    legitEvent.otherFields['dxl.certs'] = 'ca_thumb;435dfd470f727437c7cb4f07cba1f9a1f4272656'
    MessageUtils.objectToJsonPayload(legitEvent, {
      agentGuid: '{abc5d2c6-e959-11e3-baeb-005056c00009}',
      name: 'LEGIT.EXE'
    })
    dxlClient.registered[detectionTopic][0](legitEvent)
    expect(received).to.have.lengthOf(1)
    expect(received[0].name).to.equal('LEGIT.EXE')

    // (a) Missing, empty, '{}', or ':victim' agentGuid must fail closed when verifySource is true
    const invalidGuids = [undefined, '', '{}', ':foo', ':victim', 12345]
    invalidGuids.forEach(function (badGuid) {
      const badEvent = new dxl.Event(detectionTopic)
      badEvent.sourceClientId = '{abc5d2c6-e959-11e3-baeb-005056c00009}'
      const body = { name: 'BYPASS.EXE' }
      if (typeof badGuid !== 'undefined') {
        body.agentGuid = badGuid
      }
      MessageUtils.objectToJsonPayload(badEvent, body)
      dxlClient.registered[detectionTopic][0](badEvent)
    })
    expect(received).to.have.lengthOf(1)

    // (b) Match via broker-stamped sourceClientInstanceId ('<cert_sha1>:{<client_uuid>}')
    const brokerEvent = new dxl.Event(detectionTopic)
    brokerEvent.sourceClientId = '65e7960d7bd6b5b7085f9928f8b2374351ca66fb'
    brokerEvent.sourceClientInstanceId =
      '65e7960d7bd6b5b7085f9928f8b2374351ca66fb:{abc5d2c6-e959-11e3-baeb-005056c00009}'
    MessageUtils.objectToJsonPayload(brokerEvent, {
      agentGuid: '{abc5d2c6-e959-11e3-baeb-005056c00009}',
      name: 'BROKER_INSTANCE_MATCH.EXE'
    })
    dxlClient.registered[detectionTopic][0](brokerEvent)
    expect(received).to.have.lengthOf(2)
    expect(received[1].name).to.equal('BROKER_INSTANCE_MATCH.EXE')

    // (c) Match via dxl.certs leaf thumbprint
    const certEvent = new dxl.Event(detectionTopic)
    certEvent.sourceClientId = '{99999999-8888-7777-6666-555555555555}'
    certEvent.otherFields['dxl.certs'] = 'root_ca;435DFD470F727437C7CB4F07CBA1F9A1F4272656'
    MessageUtils.objectToJsonPayload(certEvent, {
      agentGuid: '435dfd470f727437c7cb4f07cba1f9a1f4272656',
      name: 'CERT_MATCH.EXE'
    })
    dxlClient.registered[detectionTopic][0](certEvent)
    expect(received).to.have.lengthOf(3)
    expect(received[2].name).to.equal('CERT_MATCH.EXE')

    // Malformed / non-object JSON payload must not throw
    const badJsonEvent = new dxl.Event(detectionTopic)
    badJsonEvent.payload = '["not-an-object"]'
    expect(function () {
      dxlClient.registered[detectionTopic][0](badJsonEvent)
    }).to.not.throw()
  })
})
