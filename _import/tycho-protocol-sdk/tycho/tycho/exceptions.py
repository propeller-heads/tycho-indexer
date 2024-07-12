from decimal import Decimal


class TychoDecodeError(Exception):
    def __init__(self, msg: str, pool_id: str):
        super().__init__(msg)
        self.pool_id = pool_id


class APIRequestError(Exception):
    pass


class TradeSimulationException(Exception):
    def __init__(self, message, pool_id: str):
        self.pool_id = pool_id
        super().__init__(message)


class RecoverableSimulationException(TradeSimulationException):
    """Marks that the simulation could not fully fulfill the requested order.

    Provides a partial trade that is valid but does not fully fulfill the conditions
    requested.

    Parameters
    ----------
    message
        Error message
    pool_id
        ID of a pool that caused the error
    partial_trade
        A tuple of (bought_amount, gas_used, new_pool_state, sold_amount)
    """

    def __init__(
        self,
        message,
        pool_id: str,
        partial_trade: tuple[Decimal, int, "ThirdPartyPool", Decimal] = None,
    ):
        super().__init__(message, pool_id)
        self.partial_trade = partial_trade


class OutOfGas(RecoverableSimulationException):
    """This exception indicates that the underlying VM **likely** ran out of gas.

    It is not easy to judge whether it was really due to out of gas, as the details
    of the SC being called might be hiding this. E.g. out of gas may happen while
    calling an external contract, which might show as the external call failing, although
    it was due to a lack of gas.
    """

    pass
