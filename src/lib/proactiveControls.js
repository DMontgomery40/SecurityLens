import { proactiveControlsData } from './proactiveControlsData';

export const proactiveControls = {
  sqlInjection: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS
  },
  commandExecution: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS
  },
  brokenAuth: {
    title: 'C6: Implement Digital Identity',
    content: proactiveControlsData.C6_DIGITAL_IDENTITY
  },
  sensitiveExposure: {
    title: 'C8: Protect Data Everywhere',
    content: proactiveControlsData.C8_PROTECT_DATA
  },
  xssVulnerability: {
    title: 'C4: Encode and Escape Data',
    content: proactiveControlsData.C4_ENCODE_ESCAPE
  },
  brokenAccessControl: {
    title: 'C7: Enforce Access Controls',
    content: proactiveControlsData.C7_ACCESS_CONTROLS
  },
  securityMisconfig: {
    title: 'C10: Handle All Errors and Exceptions',
    content: proactiveControlsData.C10_ERROR_HANDLING
  },
  insecureDeserialization: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS
  }
}; 