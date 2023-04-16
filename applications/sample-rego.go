package kubernetes.security.aws

deny[list] {
    input.kind == "Secret"
    input.apiVersion == "v1"
    // Nigel used regular expressions to match 'S3' contexts
    "s3" in [bucket | bucket := input.data[_] | re_match("^https://s3.amazonaws.com/[a-zA-Z0-9-_.]{1,255}$", string(bucket))]
}
