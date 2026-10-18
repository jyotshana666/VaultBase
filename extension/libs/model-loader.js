// VaultBase — XHR-based Model Loader for Chrome Extensions
// Completely bypasses face-api.js's loadFromUri() and TF.js's internal fetch.
// Loads model manifests and weight shards via XMLHttpRequest, decodes quantized
// weights manually, and feeds Float32Arrays directly to face-api networks.
"use strict";

// ── XHR file loader (100% reliable in Chrome extension popups) ───────────────
function xhrLoad(url, responseType) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, true);
    xhr.responseType = responseType;
    xhr.onload = () => {
      if (xhr.status === 200 || xhr.status === 0) {
        resolve(xhr.response);
      } else {
        reject(new Error("[XHR] " + xhr.status + " for " + url.split("/").pop()));
      }
    };
    xhr.onerror = () =>
      reject(new Error("[XHR] Network error: " + url.split("/").pop()));
    xhr.send();
  });
}

// ── Decode quantized/raw weights from binary shard buffer ────────────────────
function decodeWeights(buffer, weightSpecs) {
  const result = new Map();
  const view = new DataView(buffer);
  let offset = 0;

  for (const spec of weightSpecs) {
    const numElements = spec.shape.reduce((a, b) => a * b, 1);
    let data;

    if (spec.quantization && spec.quantization.dtype === "uint8") {
      // Dequantize: float = uint8_value * scale + min
      const scale = spec.quantization.scale;
      const min = spec.quantization.min;
      data = new Float32Array(numElements);
      for (let i = 0; i < numElements; i++) {
        data[i] = view.getUint8(offset + i) * scale + min;
      }
      offset += numElements; // 1 byte per uint8 value
    } else {
      // Raw float32
      data = new Float32Array(numElements);
      for (let i = 0; i < numElements; i++) {
        data[i] = view.getFloat32(offset + i * 4, true); // little-endian
      }
      offset += numElements * 4; // 4 bytes per float32
    }

    result.set(spec.name, { data, shape: spec.shape });
  }

  return result;
}

// ── Load a single face-api model entirely via XHR ────────────────────────────
async function loadModelXHR(net, manifestFilename) {
  const baseUrl = chrome.runtime.getURL("models") + "/";

  // 1. Load manifest JSON
  const manifestText = await xhrLoad(baseUrl + manifestFilename, "text");
  const manifest = JSON.parse(manifestText);
  const weightSpecs = manifest[0].weights;
  const shardPaths = manifest[0].paths;

  // 2. Load all weight shard files
  const shardBuffers = [];
  for (const shardPath of shardPaths) {
    const buf = await xhrLoad(baseUrl + shardPath, "arraybuffer");
    shardBuffers.push(buf);
  }

  // 3. Concatenate shards into single buffer
  let fullBuffer;
  if (shardBuffers.length === 1) {
    fullBuffer = shardBuffers[0];
  } else {
    const totalSize = shardBuffers.reduce((s, b) => s + b.byteLength, 0);
    const combined = new Uint8Array(totalSize);
    let off = 0;
    for (const buf of shardBuffers) {
      combined.set(new Uint8Array(buf), off);
      off += buf.byteLength;
    }
    fullBuffer = combined.buffer;
  }

  // 4. Decode all weights
  const weightMap = decodeWeights(fullBuffer, weightSpecs);

  // 5. Try to load via weight map (preferred, preserves naming)
  const tf = (typeof faceapi !== "undefined" && faceapi.tf) || window.tf;

  if (tf && typeof tf.tensor === "function" && typeof net.loadFromWeightMap === "function") {
    // Build a tf.NamedTensorMap
    const namedMap = {};
    for (const [name, { data, shape }] of weightMap) {
      namedMap[name] = tf.tensor(data, shape);
    }
    await net.loadFromWeightMap(namedMap);
    return;
  }

  // 6. Fallback: concatenate all weights into flat Float32Array
  //    and use net.load(Float32Array) which calls extractWeights internally
  let totalFloats = 0;
  for (const { data } of weightMap.values()) {
    totalFloats += data.length;
  }
  const flat = new Float32Array(totalFloats);
  let pos = 0;
  for (const { data } of weightMap.values()) {
    flat.set(data, pos);
    pos += data.length;
  }
  await net.load(flat);
}

// ── Public: load all 4 face-api models via XHR ───────────────────────────────
async function loadAllModelsXHR() {
  const models = [
    {
      net: faceapi.nets.tinyFaceDetector,
      manifest: "tiny_face_detector_model-weights_manifest.json",
      label: "tinyFaceDetector",
    },
    {
      net: faceapi.nets.faceLandmark68TinyNet,
      manifest: "face_landmark_68_tiny_model-weights_manifest.json",
      label: "faceLandmark68TinyNet",
    },
    {
      net: faceapi.nets.faceExpressionNet,
      manifest: "face_expression_model-weights_manifest.json",
      label: "faceExpressionNet",
    },
    {
      net: faceapi.nets.faceRecognitionNet,
      manifest: "face_recognition_model-weights_manifest.json",
      label: "faceRecognitionNet",
    },
  ];

  for (const { net, manifest, label } of models) {
    await loadModelXHR(net, manifest);
    console.log("[ModelLoader] ✓", label, "loaded via XHR");
  }
}
