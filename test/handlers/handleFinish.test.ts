import sinon from 'sinon';
import { expect } from 'chai';

import V6_JSON_BUFFER from '../__mocks__/v6-json-buffer.json';
import V6_JSON_BUFFER_EMPTY from '../__mocks__/v6-json-buffer-empty.json';

import handleFinish from '../../src/handlers/handleFinish';

describe('Events handling', () => {
  it('should exit if unable to process the JSON buffer', () => {
    const processStub = sinon.stub(process, 'exit');
    const consoleStub = sinon.stub(console, 'error');
    const jsonBuffer = '';
    const auditLevel = 'info';
    const exceptionIds: number[] = [];
    const filter = false;

    expect(processStub.called).to.equal(false);
    expect(consoleStub.called).to.equal(false);

    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);

    expect(processStub.called).to.equal(true);
    expect(processStub.calledWith(1)).to.equal(true);

    expect(consoleStub.called).to.equal(true);
    expect(consoleStub.calledWith('Unable to process the JSON buffer string.')).to.equal(true);

    processStub.restore();
    consoleStub.restore();
  });

  it('should be able to handle success case properly', () => {
    const processStub = sinon.stub(process, 'exit');
    const consoleStub = sinon.stub(console, 'info');
    const jsonBuffer = JSON.stringify(V6_JSON_BUFFER_EMPTY);
    const auditLevel = 'info';
    const exceptionIds: number[] = [];
    const filter = false;

    expect(consoleStub.called).to.equal(false);
    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);

    expect(processStub.called).to.equal(true);
    expect(processStub.calledWith(0)).to.equal(true);

    expect(consoleStub.called).to.equal(true);
    expect(consoleStub.calledWith('🤝  All good!')).to.equal(true);

    processStub.restore();
    consoleStub.restore();
  });

  it('should be able to except vulnerabilities properly', () => {
    const processStub = sinon.stub(process, 'exit');
    const consoleStub = sinon.stub(console, 'info');
    const jsonBuffer = JSON.stringify(V6_JSON_BUFFER);
    const auditLevel = 'info';
    const exceptionIds = [975, 976, 985, 1084, 1179, 1213, 1500, 1523, 1555, 1556, 1589];
    const filter = false;

    expect(consoleStub.called).to.equal(false);
    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);

    expect(processStub.called).to.equal(true);
    expect(processStub.calledWith(0)).to.equal(true);

    expect(consoleStub.called).to.equal(true);
    expect(consoleStub.calledWith('🤝  All good!')).to.equal(true);

    processStub.restore();
    consoleStub.restore();
  });

  it('should be able to handle found vulnerabilities properly', () => {
    const processStub = sinon.stub(process, 'exit');
    const consoleErrorStub = sinon.stub(console, 'error');
    const consoleInfoStub = sinon.stub(console, 'info');
    const jsonBuffer = JSON.stringify(V6_JSON_BUFFER);
    const auditLevel = 'info';
    const exceptionIds = [975, 976, 985, 1084, 1179, 1213, 1500, 1523, 1555];
    const filter = false;

    expect(processStub.called).to.equal(false);
    expect(consoleErrorStub.called).to.equal(false);
    expect(consoleInfoStub.called).to.equal(false);

    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);

    expect(processStub.called).to.equal(true);
    expect(consoleErrorStub.called).to.equal(true);
    expect(consoleInfoStub.called).to.equal(true); // Print security report

    expect(processStub.calledWith(1)).to.equal(true);
    expect(consoleErrorStub.calledWith('2 vulnerabilities found. Node security advisories: 1556, 1589')).to.equal(true);

    processStub.restore();
    consoleErrorStub.restore();
    consoleInfoStub.restore();
  });

  it('should inform the developer when exceptionsIds are unused', () => {
    const processStub = sinon.stub(process, 'exit');
    const consoleErrorStub = sinon.stub(console, 'error');
    const consoleWarnStub = sinon.stub(console, 'warn');
    const consoleInfoStub = sinon.stub(console, 'info');
    const jsonBuffer = JSON.stringify(V6_JSON_BUFFER);
    const auditLevel = 'info';
    const filter = false;

    let exceptionIds = [975, 976, 985, 1084, 1179, 1213, 1500, 1523, 1555, 2001];

    expect(processStub.called).to.equal(false);
    expect(consoleErrorStub.called).to.equal(false);
    expect(consoleWarnStub.called).to.equal(false);
    expect(consoleInfoStub.called).to.equal(false);

    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);

    expect(processStub.called).to.equal(true);
    expect(processStub.calledWith(1)).to.equal(true);
    expect(consoleErrorStub.called).to.equal(true);
    expect(consoleErrorStub.calledWith('2 vulnerabilities found. Node security advisories: 1556, 1589')).to.equal(true);

    expect(consoleInfoStub.called).to.equal(true); // Print security report
    expect(consoleWarnStub.called).to.equal(true);

    // Message for one unused exception
    // eslint-disable-next-line max-len
    let message = `1 of the excluded vulnerabilities did not match any of the found vulnerabilities: 2001. It can be removed from the .nsprc file or --exclude -x flags.`;
    expect(consoleWarnStub.calledWith(message)).to.equal(true);

    // Message for multiple unused exceptions
    exceptionIds = [975, 976, 985, 1084, 1179, 1213, 1500, 1523, 1555, 2001, 2002];
    handleFinish(jsonBuffer, auditLevel, exceptionIds, filter);
    // eslint-disable-next-line max-len
    message = `2 of the excluded vulnerabilities did not match any of the found vulnerabilities: 2001, 2002. They can be removed from the .nsprc file or --exclude -x flags.`;
    expect(consoleWarnStub.calledWith(message)).to.equal(true);

    processStub.restore();
    consoleErrorStub.restore();
    consoleWarnStub.restore();
    consoleInfoStub.restore();
  });
});
