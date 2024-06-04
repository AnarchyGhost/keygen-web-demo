<template>
  <v-card class="fill-height pt-16">
    <v-card-text>
      <v-col>
      <v-row>
          <v-textarea v-model="privateKey" readonly rows="25"/>
          <v-textarea v-model="publicKey" readonly rows="25"/>
          <v-textarea v-model="csr" readonly rows="25"/>
      </v-row>

          <v-row>
            <v-text-field v-model="certificateForm.CN" label="Common Name*"/>
            <v-text-field v-model="certificateForm.C" label="Country"/>
          </v-row>
          <v-row>
            <v-text-field v-model="certificateForm.ST" label="State"/>
            <v-text-field v-model="certificateForm.L" label="Locality"/>
          </v-row>
          <v-row>
            <v-text-field v-model="certificateForm.O" label="Organisation"/>
            <v-text-field v-model="certificateForm.OU" label="Organisational Unit"/>
          </v-row>
          <v-row>
            <v-text-field v-model="certificateForm.EMAIL" label="Email"/>
          </v-row>
        <v-row>
          <v-btn :disabled="isCSRGenerationDisabled" text="Generate" @click="generate"/>
        </v-row>
      </v-col>
    </v-card-text>
  </v-card>
</template>

<script lang="ts">

import {BasicConstraintsExtension, KeyUsageFlags, KeyUsagesExtension, X509CertificateGenerator} from "@peculiar/x509";

export default {
  data() {
      return {
        publicKey: null,
        privateKey: null,
        keyPair: null,
        csr: null,
        certificateForm: {
          CN: null,
          O: null,
          OU: null,
          L: null,
          ST: null,
          C: null,
          EMAIL: null,
        }
      }
  },
  computed: {
    isCSRGenerationDisabled() {
      return !this.certificateForm.CN?.length;
    },

  },
  methods: {
    async generate() {
      await this.generateKeys();
      await this.generateCSR();
    },
    getCertSubject() {
      let result = [];
      for (const certificateFormKey in this.certificateForm) {
        if (this.certificateForm[certificateFormKey]?.length) {
          result.push(`${certificateFormKey}=${this.certificateForm[certificateFormKey]}`);
        }
      }
      return result.join(', ');
    },
    async generateCSR() {
      const alg = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
      };

      let keyUsages = KeyUsageFlags.digitalSignature;

      const extensions = [
        new BasicConstraintsExtension(false, undefined, true)
      ];

      if (keyUsages) {
        extensions.push(new KeyUsagesExtension(keyUsages, true));
      }

      const cert = await X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: this.getCertSubject(),
        signingAlgorithm: alg,
        keys: this.keyPair,
        extensions
      });

      this.csr = cert.toString("pem")
    },
    async generateKeys() {
      this.keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
      );

      this.privateKey = await this.exportPrivateKey(this.keyPair);
      this.publicKey = await this.exportPublicKey(this.keyPair);

    },
    async exportPrivateKey(keyPair: CryptoKeyPair): Promise<String> {
      const binary = (await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
      const base64 = btoa(
        new Uint8Array(binary)
          .reduce((data, byte) => data + String.fromCharCode(byte), '')
      );
      return `
      -----BEGIN RSA PRIVATE KEY-----${base64}
      -----END RSA PRIVATE KEY-----
      `
    },
    async exportPublicKey(keyPair: CryptoKeyPair): Promise<String> {
      const binary = (await window.crypto.subtle.exportKey('spki', keyPair.publicKey))
      const base64 = btoa(
        new Uint8Array(binary)
          .reduce((data, byte) => data + String.fromCharCode(byte), '')
      );
      return `
      -----BEGIN PUBLIC KEY-----${base64}
      -----END PUBLIC KEY-----
      `
    }
  }
}
</script>
