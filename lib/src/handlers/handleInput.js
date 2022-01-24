"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_get_1 = __importDefault(require("lodash.get"));
var common_1 = require("../utils/common");
var file_1 = require("../utils/file");
var vulnerability_1 = require("../utils/vulnerability");
/**
 * Handle user's input
 * @param  {Object} options     User's command options or flags
 * @param  {Function} fn        The function to handle the inputs
 */
function handleInput(options, fn) {
    // Generate NPM Audit command
    var auditCommand = [
        'npm audit',
        // flags
        lodash_get_1.default(options, 'production') ? '--production' : '',
        lodash_get_1.default(options, 'registry') ? "--registry=" + options.registry : '',
    ]
        .filter(Boolean)
        .join(' ');
    // Taking the audit level from the command or environment variable
    var envVar = process.env.NPM_CONFIG_AUDIT_LEVEL;
    var auditLevel = lodash_get_1.default(options, 'level', envVar) || 'info';
    // Taking the audit level from the command or environment variable
    var filter = lodash_get_1.default(options, 'filter') || false;
    // Get the exceptions
    var nsprc = file_1.readFile('.nsprc');
    var cmdExceptions = lodash_get_1.default(options, 'exclude', '').split(',').filter(common_1.isWholeNumber).map(Number);
    var exceptionIds = vulnerability_1.getExceptionsIds(nsprc, cmdExceptions);
    fn(auditCommand, auditLevel, exceptionIds, filter);
}
exports.default = handleInput;
