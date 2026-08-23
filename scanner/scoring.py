def severity_classifer(normalized_score):

    if normalized_score <= 0.3:
        severity = "LOW"

    elif normalized_score > 0.3 and normalized_score <= 0.7:
        severity = "MEDIUM"

    elif normalized_score > 0.7 and normalized_score <= 1.0:
        severity = "HIGH"
    return severity