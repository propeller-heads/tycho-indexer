class TychoDecodeError(Exception):
    def __init__(self, msg: str, pool_id: str):
        super().__init__(msg)
        self.pool_id = pool_id


class APIRequestError(Exception):
    pass
