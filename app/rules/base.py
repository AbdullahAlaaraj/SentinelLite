class BaseRule:
    name = "Base Rule"

    def evaluate(self, logs):
        raise NotImplementedError