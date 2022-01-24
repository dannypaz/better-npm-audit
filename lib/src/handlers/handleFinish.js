"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var print_1 = require("../utils/print");
var vulnerability_1 = require("../utils/vulnerability");
/**
 * Process and analyze the NPM audit JSON
 * @param  {String} jsonBuffer    NPM audit stringified JSON payload
 * @param  {Number} auditLevel    The level of vulnerabilities we care about
 * @param  {Array} exceptionIds   List of vulnerability IDs to exclude
 * @param  {Boolean} filter        Vulnerability level filter
 * @return {undefined}
 */
function handleFinish(jsonBuffer, auditLevel, exceptionIds, filter) {
    var _a = vulnerability_1.processAuditJson(jsonBuffer, auditLevel, exceptionIds, filter), unhandledIds = _a.unhandledIds, vulnerabilityIds = _a.vulnerabilityIds, report = _a.report, failed = _a.failed;
    // If unable to process the audit JSON
    if (failed) {
        console.error('Unable to process the JSON buffer string.');
        // Exit failed
        process.exit(1);
        return;
    }
    // Print the security report
    if (report.length) {
        print_1.printSecurityReport(report);
    }
    // Grab any un-filtered vulnerabilities at the appropriate level
    var unusedExceptionIds = exceptionIds.filter(function (id) { return !vulnerabilityIds.includes(id); });
    // Display the unused exceptionId's
    if (unusedExceptionIds.length) {
        var messages = [
            unusedExceptionIds.length + " of the excluded vulnerabilities did not match any of the found vulnerabilities: " + unusedExceptionIds.join(', ') + ".",
            (unusedExceptionIds.length > 1 ? 'They' : 'It') + " can be removed from the .nsprc file or --exclude -x flags.",
        ];
        console.warn(messages.join(' '));
    }
    // Display the found unhandled vulnerabilities
    if (unhandledIds.length) {
        console.error(unhandledIds.length + " vulnerabilities found. Node security advisories: " + unhandledIds.join(', '));
        // Exit failed
        process.exit(1);
    }
    else {
        // Happy happy, joy joy
        console.info('🤝  All good!');
        process.exit(0);
    }
}
exports.default = handleFinish;
