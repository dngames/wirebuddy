# Image archive, software 4.2: DICOM conformance statement

The archive stores CT images that modalities and reconstruction systems send it over the DICOM
network protocol, and answers verification requests. This statement follows the structure of
DICOM PS3.2 in short.

| SOP class | UID | SCU | SCP |
|---|---|---|---|
| Verification | `1.2.840.10008.1.1` | no | yes |
| CT Image Storage | `1.2.840.10008.5.1.4.1.1.2` | no | yes |

## 1. Network

| | |
|---|---|
| AE title | `ARCHIVE` (configurable) |
| Port | TCP 11112 (configurable) |
| Application context | `1.2.840.10008.3.1.1.1` |
| Implementation class UID | `2.25.148319916397976774951993427761131673038` |
| Implementation version name | `ARCHIVE_4_2` |
| Maximum PDU length received | 16384 bytes |
| Associations | any number at once; asynchronous operations are not negotiated (one operation at a time) |

### 1.1 Association acceptance

The archive accepts associations from any calling AE title. It rejects an A-ASSOCIATE-RQ with an
A-ASSOCIATE-RJ, result 1 (rejected-permanent), when:

| Situation | Source | Reason |
|---|---|---|
| The protocol version does not include version 1 | 2 (service provider, ACSE) | 2: protocol version not supported |
| The called AE title is not the archive's | 1 (service user) | 7: called AE title not recognized |
| The application context is not the DICOM one | 1 (service user) | 2: application context name not supported |

Presentation contexts:

| Abstract syntax | Transfer syntaxes, in the archive's order of preference | Role |
|---|---|---|
| CT Image Storage | Explicit VR Little Endian `1.2.840.10008.1.2.1`, Implicit VR Little Endian `1.2.840.10008.1.2` | SCP |
| Verification | the same | SCP |

For each proposed presentation context the archive accepts the first transfer syntax of its own
list that the requestor proposed. It answers other abstract syntaxes with result 3 (abstract syntax
not supported) and contexts without a common transfer syntax with result 4 (transfer syntaxes not
supported). SCP/SCU role selection and other extended negotiation items are ignored.

### 1.2 C-STORE

The archive stores each instance under its SOP Instance UID (0008,0018), which must equal the
Affected SOP Instance UID of the request, and replaces an instance it already holds under that UID.
The dataset is kept as received: the archive does not change UIDs or other attributes.

| Status | Meaning | When |
|---|---|---|
| `0000` | Success | The instance is stored, also when it replaced one with the same SOP Instance UID |
| `0122` | Refused: SOP class not supported | A C-STORE on the Verification context, or of another SOP class |
| `C000` | Error: cannot understand | The dataset can't be read, has no Series Instance UID, or its SOP Instance UID is not the request's |

C-ECHO is answered with Success. Other DIMSE requests are answered with `0211` (unrecognized
operation).

### 1.3 Release and abort

The archive answers an A-RELEASE-RQ with an A-RELEASE-RP and closes the connection. It aborts an
association (A-ABORT, source 2) and closes the connection on:

| Reason | When |
|---|---|
| 1: unrecognized PDU | A PDU type that does not exist |
| 2: unexpected PDU | A PDU the association's state doesn't allow, e.g. P-DATA-TF before A-ASSOCIATE-RQ |
| 6: invalid PDU parameter value | A P-DATA-TF longer than 16384 bytes, a malformed PDV, a PDV on a presentation context that was not accepted, or a dataset fragment before its command |

## 2. Log

The archive logs to standard output, each line with the number of the association it is about:

```
[1] RECON at 127.0.0.1:45136: association accepted, CT Image Storage in Explicit VR Little Endian
[1] released after 184 C-STORE: 184 Success
[1] series 2 (5 mm): 24 instances
```

| Line | When |
|---|---|
| `<calling AE> at <address>: association accepted, <contexts>` | An association is accepted |
| `<calling AE> at <address>: association rejected, <reason>` | An association is rejected |
| `released after <n> C-STORE: <n> Success[, <n> failed]` | The association is released; it begins `aborted` or `closed` when it ends otherwise |
| `series <Series Number> (<Slice Thickness> mm): <n> instances` | After the association ends, for each series it stored to: how many instances of that series the archive holds now |
