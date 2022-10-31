import re

import numpy


def cvss3_att_value(cvss3_vector):
    AV = {
        'N': "Network",
        'A': "Adjacent",
        'L': "Local",
        'P': "Physical"
    }
    AC = {
        'L': "Low",
        'H': "High"
    }
    PR = {
        'N': "None",
        'L': "Low",
        'H': "High"
    }
    UI = {
        'N': "None",
        'R': "Required"
    }
    S = {
        'C': "Changed",
        'U': "Unchanged"
    }
    C = {
        'N': "None",
        'L': "Low",
        'H': "High"
    }
    I = {
        'N': "None",
        'L': "Low",
        'H': "High"
    }
    A = {
        'N': "None",
        'L': "Low",
        'H': "High"
    }

    vector = list(cvss3_vector.split('/'))
    cvss3_attack_vector = AV.get(re.sub('.*:', '', vector[0]))
    cvss3_attack_cpmplexity = AC.get(re.sub('.*:', '', vector[1]))
    cvss3_priv_required = PR.get(re.sub('.*:', '', vector[2]))
    cvss3_user_interaction = UI.get(re.sub('.*:', '', vector[3]))
    cvss3_scope = S.get(re.sub('.*:', '', vector[4]))
    cvss3_confidentiality_impact = C.get(re.sub('.*:', '', vector[5]))
    cvss3_integrity_impact = I.get(re.sub('.*:', '', vector[6]))
    cvss3_availibility_impact = A.get(re.sub('.*:', '', vector[7]))

    return cvss3_attack_vector, cvss3_attack_cpmplexity, cvss3_priv_required, cvss3_user_interaction, cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact, cvss3_availibility_impact


def cvss3severity(cvss3_score):
    score = cvss3_score

    if score == 0.0:
        return "None"
    elif score*10 in range(10, 40, 1):
        return "Low"
    elif score*10 in range(40, 70, 1):
        return "Medium"
    elif score*10 in range(70, 90, 1):
        return "High"
    elif score*10 in range(90, 101, 1):
        return "Critical"
