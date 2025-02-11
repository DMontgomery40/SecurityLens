import React from 'react';
import { jsx } from 'react/jsx-runtime';
import proactiveControlsData, { vulnerabilityGuides } from './proactiveControlsData.js';

// Style component
export function Styles() {
  return jsx("style", {
    children: `
      .example-block {
        margin: 1rem 0;
        border-radius: 0.5rem;
        overflow: hidden;
      }
      .example-label {
        padding: 0.5rem 1rem;
        font-weight: 500;
        background: rgba(0,0,0,0.2);
      }
      .code-block {
        margin: 0;
        padding: 1rem;
        background: rgba(0,0,0,0.3);
        font-family: monospace;
        font-size: 0.9rem;
        overflow-x: auto;
      }
      .code-block.bad {
        border-left: 4px solid #ef4444;
      }
      .code-block.good {
        border-left: 4px solid #22c55e;
      }
    `
  });
}

// Scan webpage source function
export const scanWebpageSource = async (url) => {
  try {
    const response = await fetch("/.netlify/functions/scan-webpage-source", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error scanning webpage:", error);
    throw error;
  }
};

// Modal component
export function Modal({ children, open, onClose }) {
  if (!open) return null;
  
  return jsx("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50",
    onClick: onClose,
    children: jsx("div", {
      className: "relative bg-gray-800 rounded-lg w-full max-w-3xl max-h-[80vh] overflow-auto p-4",
      onClick: e => e.stopPropagation(),
      children: [
        jsx("button", {
          onClick: onClose,
          className: "absolute top-3 right-3 text-gray-400 hover:text-gray-600",
          children: "✕"
        }),
        children
      ]
    })
  });
}

// Container components
export function ContentContainer({ children }) {
  return jsx("div", {
    className: "space-y-4",
    children: children
  });
}

export function Section({ children }) {
  return jsx("div", {
    className: "mb-4",
    children: children
  });
}

// Export both proactive controls and vulnerability guides
export const proactiveControls = proactiveControlsData;
export const guides = vulnerabilityGuides;